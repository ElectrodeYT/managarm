#include <async/algorithm.hpp>
#include <async/basic.hpp>
#include <async/recurring-event.hpp>
#include <async/result.hpp>
#include <arch/bit.hpp>
#include <arch/variable.hpp>
#include <helix/timer.hpp>
#include <protocols/fs/server.hpp>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <deque>
#include <format>
#include <iomanip>
#include <print>
#include <random>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

#include <bragi/helpers-std.hpp>
#include <core/dispatch.hpp>
#include <core/time.hpp>

#include "checksum.hpp"
#include "ip4.hpp"
#include "tcp-state.hpp"
#include "tcp4.hpp"

namespace {

constexpr bool debugTcp = false;
constexpr bool logDiscards = false;
constexpr uint64_t handshakeTimeout = 180 * tcp::second;
constexpr uint64_t deliveryTimeout = 300 * tcp::second;
constexpr uint64_t finishTimeout = 60 * tcp::second;
constexpr size_t maxPendingConnections = 128;
constexpr uint16_t maxPayload = 1280;
constexpr uint16_t defaultMss = 536;
using Error = protocols::fs::Error;

struct PseudoHeader {
	arch::scalar_storage<uint32_t, arch::big_endian> src;
	arch::scalar_storage<uint32_t, arch::big_endian> dst;
	uint8_t zero = 0;
	uint8_t proto = static_cast<uint8_t>(IpProto::tcp);
	arch::scalar_storage<uint16_t, arch::big_endian> len;
};

static_assert(sizeof(PseudoHeader) == 12);

// SO_RCVTIMEO/SO_SNDTIMEO: like on Linux, a zero timeval means no timeout and a negative one
// makes the calls time out at once.
std::expected<std::optional<uint64_t>, protocols::fs::Error> parseTimeout(const std::vector<char> &optbuf) {
	timeval tv;
	if(optbuf.size() < sizeof(tv))
		return std::unexpected{protocols::fs::Error::illegalArguments};
	memcpy(&tv, optbuf.data(), sizeof(tv));
	if(tv.tv_usec < 0 || tv.tv_usec >= 1'000'000)
		return std::unexpected{protocols::fs::Error::illegalArguments};
	if(!tv.tv_sec && !tv.tv_usec)
		return std::nullopt;
	return core::timevalToNanos(tv);
}

struct RingBuffer {
	RingBuffer(int shift)
	: storage_{reinterpret_cast<char *>(operator new (1 << shift))}, shift_{shift} { }

	RingBuffer(const RingBuffer &) = delete;

	~RingBuffer() {
		operator delete(storage_);
	}

	RingBuffer &operator= (const RingBuffer &) = delete;

	size_t spaceForEnqueue() {
		return (size_t{1} << shift_) - (enqPtr_ - deqPtr_);
	}

	size_t availableToDequeue() {
		return enqPtr_ - deqPtr_;
	}

	void enqueue(void *data, size_t size) {
		assert(size <= spaceForEnqueue());
		size_t ringSize = size_t{1} << shift_;
		auto wrappedPtr = enqPtr_ & (ringSize - 1);
		auto p = reinterpret_cast<char *>(data);
		size_t bytesUntilEnd = std::min(size, ringSize - wrappedPtr);
		memcpy(storage_ + wrappedPtr, p, bytesUntilEnd);
		memcpy(storage_, p + bytesUntilEnd, size - bytesUntilEnd);
		enqPtr_ += size;
	}

	void dequeueLookahead(size_t offset, void *data, size_t size) {
		assert(offset + size <= availableToDequeue());
		size_t ringSize = size_t{1} << shift_;
		auto wrappedPtr = (deqPtr_ + offset) & (ringSize - 1);
		auto p = reinterpret_cast<char *>(data);
		size_t bytesUntilEnd = std::min(size, ringSize - wrappedPtr);
		memcpy(p, storage_ + wrappedPtr, bytesUntilEnd);
		memcpy(p + bytesUntilEnd, storage_, size - bytesUntilEnd);
	}

	void dequeueAdvance(size_t size) {
		deqPtr_ += size;
	}

private:
	char *storage_;
	int shift_;
	uint64_t enqPtr_ = 0;
	uint64_t deqPtr_ = 0;
};

// TODO: Use a CSPRNG, see also UDP.
static std::mt19937 globalPrng;

} // namespace

struct TcpHeader {
	static constexpr arch::field<uint16_t, bool> finFlag{0, 1};
	static constexpr arch::field<uint16_t, bool> synFlag{1, 1};
	static constexpr arch::field<uint16_t, bool> rstFlag{2, 1};
	static constexpr arch::field<uint16_t, bool> ackFlag{4, 1};
	static constexpr arch::field<uint16_t, unsigned int> headerWords{12, 4};

	arch::scalar_storage<uint16_t, arch::big_endian> srcPort;
	arch::scalar_storage<uint16_t, arch::big_endian> destPort;
	arch::scalar_storage<uint32_t, arch::big_endian> seqNumber;
	arch::scalar_storage<uint32_t, arch::big_endian> ackNumber;
	arch::bit_storage<uint16_t, arch::big_endian> flags;
	arch::scalar_storage<uint16_t, arch::big_endian> window;
	arch::scalar_storage<uint16_t, arch::big_endian> checksum;
	arch::scalar_storage<uint16_t, arch::big_endian> urgentPointer;
};

static_assert(sizeof(TcpHeader) == 20);

struct TcpPacket {
	arch::dma_buffer_view payload() const {
		auto words = header.flags.load() & TcpHeader::headerWords;
		return packet->payload().subview(words * 4);
	}

	bool syn() const { return header.flags.load() & TcpHeader::synFlag; }
	bool fin() const { return header.flags.load() & TcpHeader::finFlag; }
	bool rst() const { return header.flags.load() & TcpHeader::rstFlag; }
	bool ack() const { return header.flags.load() & TcpHeader::ackFlag; }
	uint32_t sequenceLength() const { return payload().size() + syn() + fin(); }

	uint16_t mss() const {
		auto words = header.flags.load() & TcpHeader::headerWords;
		auto options = packet->payload().subview(sizeof(TcpHeader), words * 4 - sizeof(TcpHeader));
		auto data = reinterpret_cast<const uint8_t *>(options.data());
		for(size_t i = 0; i < options.size();) {
			auto kind = data[i];
			if(!kind)
				break;
			if(kind == 1) {
				++i;
				continue;
			}
			if(i + 1 >= options.size() || data[i + 1] < 2 || data[i + 1] > options.size() - i)
				break;
			auto length = data[i + 1];
			if(kind == 2 && length == 4) {
				uint16_t value = (data[i + 2] << 8) | data[i + 3];
				return value ? value : defaultMss;
			}
			i += length;
		}
		return defaultMss;
	}

	bool parse(smarter::shared_ptr<const Ip4Packet> packet) {
		auto ipPayload = packet->payload();
		if (ipPayload.size() < sizeof(TcpHeader)) {
			if (logDiscards)
				std::println("netserver: Discarding TCP packet smaller than the header");
			return false;
		}

		std::memcpy(&header, ipPayload.data(), sizeof(TcpHeader));
		auto words = header.flags.load() & TcpHeader::headerWords;
		if (words * 4 < sizeof(TcpHeader)) {
			if (logDiscards)
				std::println("netserver: Discarding TCP packet with a data offset below 5");
			return false;
		}
		if (ipPayload.size() < words * 4) {
			if (logDiscards)
				std::println("netserver: Discarding TCP packet smaller than its data offset");
			return false;
		}

		// Unlike UDP, TCP always carries a checksum.
		PseudoHeader pseudo {
			.src = packet->header.source,
			.dst = packet->header.destination,
			.proto = packet->header.protocol,
			.len = ipPayload.size()
		};
		Checksum csum;
		csum.update(&pseudo, sizeof(pseudo));
		csum.update(ipPayload);
		auto result = csum.finalize();
		if (result && ~result) {
			if (logDiscards)
				std::println("netserver: Discarding TCP packet with invalid checksum");
			return false;
		}

		this->packet = std::move(packet);
		return true;
	}

	// arch::basic_storage::load() reads the header but is not const-qualified.
	mutable TcpHeader header;
	smarter::shared_ptr<const Ip4Packet> packet;
};

namespace {

struct Segment {
	uint32_t seq;
	uint32_t ack = 0;
	uint16_t window = 0;
	uint16_t mss = 0;
	bool syn = false;
	bool fin = false;
	bool rst = false;
	bool ackFlag = false;
};

std::vector<char> encodeSegment(TcpEndpoint local, TcpEndpoint remote, Segment segment,
		size_t payloadSize = 0) {
	size_t headerSize = sizeof(TcpHeader) + (segment.mss ? 4 : 0);
	std::vector<char> buf(headerSize + payloadSize);
	auto header = new (buf.data()) TcpHeader {
		.srcPort = local.port,
		.destPort = remote.port,
		.seqNumber = segment.seq,
		.ackNumber = segment.ack,
		.flags = {},
		.window = segment.window,
		.checksum = 0,
		.urgentPointer = 0,
	};
	header->flags.store(TcpHeader::headerWords(headerSize / 4)
			| TcpHeader::synFlag(segment.syn) | TcpHeader::finFlag(segment.fin)
			| TcpHeader::rstFlag(segment.rst) | TcpHeader::ackFlag(segment.ackFlag));
	if(segment.mss) {
		auto option = reinterpret_cast<uint8_t *>(buf.data() + sizeof(TcpHeader));
		option[0] = 2;
		option[1] = 4;
		option[2] = segment.mss >> 8;
		option[3] = segment.mss & 0xff;
	}
	return buf;
}

void checksumSegment(std::vector<char> &buf, TcpEndpoint local, TcpEndpoint remote) {
	PseudoHeader pseudo{.src = local.ipAddress, .dst = remote.ipAddress, .len = buf.size()};
	Checksum csum;
	csum.update(&pseudo, sizeof(pseudo));
	csum.update(buf.data(), buf.size());
	reinterpret_cast<TcpHeader *>(buf.data())->checksum = csum.finalize();
}

uint16_t localMss(const Ip4TargetInfo &target) {
	auto mtu = target.link->mtu;
	if(target.route.mtu)
		mtu = std::min<uint32_t>(mtu, target.route.mtu);
	constexpr auto headers = sizeof(TcpHeader) + sizeof(Ip4Packet::Header);
	return mtu > headers ? std::min<size_t>(mtu - headers, maxPayload) : 1;
}

async::result<void> sendReset(TcpEndpoint local, TcpEndpoint remote, Segment reset,
		std::shared_ptr<nic::Link> boundInterface = {}) {
	auto target = co_await ip4().targetByRemote(remote.ipAddress, std::move(boundInterface));
	if(!target)
		co_return;
	target->source = local.ipAddress;
	auto buf = encodeSegment(local, remote, reset);
	checksumSegment(buf, local, remote);
	co_await ip4().sendFrame(std::move(*target), buf.data(), buf.size(), static_cast<uint16_t>(IpProto::tcp));
}

void replyReset(const TcpPacket &packet, std::shared_ptr<nic::Link> boundInterface = {}) {
	if(packet.rst())
		return;
	TcpEndpoint local{packet.packet->header.destination, packet.header.destPort.load()};
	TcpEndpoint remote{packet.packet->header.source, packet.header.srcPort.load()};
	Segment reset{.seq = packet.ack() ? packet.header.ackNumber.load() : 0, .rst = true};
	if(!packet.ack()) {
		reset.ack = packet.header.seqNumber.load() + packet.sequenceLength();
		reset.ackFlag = true;
	}
	async::detach(sendReset(local, remote, reset, std::move(boundInterface)));
}

protocols::fs::Error checkAddress(const void *addrPtr, size_t addrLength, TcpEndpoint &e) {
	struct sockaddr_in sa;
	if (addrLength < sizeof(sa))
		return protocols::fs::Error::illegalArguments;

	std::memcpy(&sa, addrPtr, sizeof(sa));
	if (sa.sin_family != AF_INET)
		return protocols::fs::Error::afNotSupported;

	e.port = arch::from_endian<arch::big_endian, uint16_t>(sa.sin_port);
	e.ipAddress = arch::from_endian<arch::big_endian, uint32_t>(sa.sin_addr.s_addr);
	return protocols::fs::Error::none;
}

} // anonymous namespace

static async::result<void> serveLanes(
	helix::UniqueLane ctrlLane,
	helix::UniqueLane ptLane,
	smarter::shared_ptr<Tcp4Socket> sock);

struct Tcp4Socket {
	Tcp4Socket(Tcp4 *parent, bool nonBlock)
	: parent_(parent), nonBlock_{nonBlock}, sendRing_{14} {}

	void disconnect();

	static auto makeSocket(Tcp4 *parent, bool nonBlock) {
		auto s = smarter::make_shared<Tcp4Socket>(parent, nonBlock);
		s->holder_ = s;
		return s;
	}

	static async::result<protocols::fs::Error> bind(void *object,
			helix_ng::CredentialsView creds,
			const void *addrPtr, size_t addrLength) {
		(void) creds;

		auto self = static_cast<Tcp4Socket *>(object);

		if (self->localEp_.port)
			co_return protocols::fs::Error::illegalArguments;

		// Validate the endpoint.
		TcpEndpoint bindEp;
		if (auto e = checkAddress(addrPtr, addrLength, bindEp); e != protocols::fs::Error::none)
			co_return e;

		if (bindEp.ipAddress == INADDR_BROADCAST) {
			std::cout << "netserver: TCP cannot broadcast" << std::endl;
			co_return protocols::fs::Error::accessDenied;
		}

		if (bindEp.ipAddress != INADDR_ANY && !ip4().hasIp(bindEp.ipAddress)) {
			std::cout << "netserver: IP address " << std::setw(8) << std::hex << bindEp.ipAddress << std::dec << " is not available" << std::endl;
			co_return protocols::fs::Error::addressNotAvailable;
		}

		// Bind the socket.
		if (!bindEp.port) {
			if (!self->bindAvailable(bindEp.ipAddress, true)) {
				std::cout << "netserver: No source port" << std::endl;
				co_return protocols::fs::Error::addressInUse;
			}
		} else if (!self->parent_->tryBind(self->holder_.lock(), true, bindEp)) {
			co_return protocols::fs::Error::addressInUse;
		}

		co_return protocols::fs::Error::none;
	}

	static async::result<size_t> sockname(void *object, void *addr_ptr, size_t max_addr_length) {
		auto self = static_cast<Tcp4Socket *>(object);
		sockaddr_in sa{};
		sa.sin_family = AF_INET;
		sa.sin_port = htons(self->localEp_.port);
		sa.sin_addr.s_addr = htonl(self->localEp_.ipAddress);
		memcpy(addr_ptr, &sa, std::min(sizeof(sockaddr_in), max_addr_length));

		co_return sizeof(sockaddr_in);
	}

	static async::result<frg::expected<protocols::fs::Error, size_t>> peername(void *object, void *addr_ptr, size_t max_addr_length) {
		auto self = static_cast<Tcp4Socket *>(object);
		if(!self->synchronized_()) {
			co_return protocols::fs::Error::notConnected;
		}
		sockaddr_in sa{};
		sa.sin_family = AF_INET;
		sa.sin_port = htons(self->remoteEp_.port);
		sa.sin_addr.s_addr = htonl(self->remoteEp_.ipAddress);
		memcpy(addr_ptr, &sa, std::min(sizeof(sockaddr_in), max_addr_length));

		co_return sizeof(sockaddr_in);
	}

	struct HandleIoctl {
		async::result<std::expected<void, DispatchError>> operator() (managarm::fs::GenericIoctlRequest &&req, helix::BorrowedDescriptor conversation, bragi::preamble, Tcp4Socket *self) {
			managarm::fs::GenericIoctlReply resp;

			switch(req.command()) {
				case FIONREAD: {
					resp.set_error(managarm::fs::Errors::SUCCESS);

					if(!self->synchronized_() && self->pendingError_ == Error::none
							&& !self->receive_.readable()) {
						resp.set_error(managarm::fs::Errors::NOT_CONNECTED);
					}else {
						resp.set_fionread_count(self->receive_.readable());
					}
					break;
				}
				default: {
					std::cout << "Invalid ioctl for tcp-socket" << std::endl;
					resp.set_error(managarm::fs::Errors::ILLEGAL_ARGUMENT);
					break;
				}
			}

			auto ser = resp.SerializeAsString();
			auto [send_resp] = co_await helix_ng::exchangeMsgs(
				conversation,
				helix_ng::sendBuffer(ser.data(), ser.size())
			);
			HEL_CHECK(send_resp.error());

			co_return {};
		}
	};

	static async::result<void> ioctl(void *object, uint32_t, helix_ng::RecvInlineResult msg, helix::UniqueLane conversation) {
		auto self = static_cast<Tcp4Socket *>(object);

		auto res = co_await dispatchRequest<
			managarm::fs::GenericIoctlRequest
		>(conversation, std::move(msg), HandleIoctl{}, self);

		if (!res) {
			auto [dismiss] = co_await helix_ng::exchangeMsgs(
				conversation, helix_ng::dismiss());
			HEL_CHECK(dismiss.error());
		}
	}

	static async::result<protocols::fs::Error> connect(void *object,
			helix_ng::CredentialsView creds,
			const void *addrPtr, size_t addrLength) {
		(void) creds;

		auto self = static_cast<Tcp4Socket *>(object);

		if (self->connectState_ != ConnectState::none || self->listening_)
			co_return protocols::fs::Error::illegalArguments;

		// Validate the endpoint.
		TcpEndpoint connectEp;
		if (auto e = checkAddress(addrPtr, addrLength, connectEp); e != protocols::fs::Error::none)
			co_return e;

		if (connectEp.ipAddress == INADDR_BROADCAST) {
			std::cout << "netserver: TCP cannot broadcast" << std::endl;
			co_return protocols::fs::Error::accessDenied;
		}

		// Like Linux, fix the source address at connect time so that getsockname() and the
		// demultiplexing in Tcp4::feedDatagram() see the address that the segments carry.
		auto targetInfo = co_await ip4().targetByRemote(connectEp.ipAddress, self->boundInterface_);
		if (!targetInfo)
			co_return protocols::fs::Error::netUnreachable;
		if (self->connectState_ != ConnectState::none || self->listening_)
			co_return protocols::fs::Error::illegalArguments;

		// Bind the socket if necessary.
		if (self->bound_)
			self->originalBind_ = self->localEp_;
		if (!self->bound_) {
			if (!self->bindAvailable(targetInfo->source, true)) {
				std::cout << "netserver: No source port" << std::endl;
				co_return protocols::fs::Error::addressNotAvailable;
			}
		} else if (self->localEp_.ipAddress == INADDR_ANY) {
			// Narrowing a unique wildcard bind to one address cannot conflict.
			self->parent_->rebind(self, {targetInfo->source, self->localEp_.port});
		}

		auto attempt = std::make_shared<ConnectAttempt>();
		self->connectAttempt_ = attempt;
		self->startHandshake_(ConnectState::sendSyn, connectEp, localMss(*targetInfo));
		while(!attempt->result)
			co_await self->settleEvent_.async_wait();
		co_return *attempt->result;
	}

	static async::result<protocols::fs::Error> listen(void *object) {
		auto self = static_cast<Tcp4Socket *>(object);
		if(self->connectState_ != ConnectState::none)
			co_return Error::illegalArguments;
		if(!self->bound_ && !self->bindAvailable(INADDR_ANY, true))
			co_return Error::addressInUse;
		self->listening_ = true;

		co_return protocols::fs::Error::none;
	}

	static async::result<frg::expected<protocols::fs::Error, protocols::fs::AcceptResult>> accept(void *object) {
		auto self = static_cast<Tcp4Socket *>(object);

		if(self->pendingConnections_.empty()) {
			if(!self->listening_)
				co_return Error::illegalArguments;
			if(self->nonBlock_)
				co_return protocols::fs::Error::wouldBlock;

			auto deadline = helix::deadlineAfter(self->recvTimeoutNs_);
			while(self->pendingConnections_.empty()) {
				if(!self->listening_)
					co_return Error::illegalArguments;
				auto raised = co_await helix::withTimeout([&](async::cancellation_token ct) {
					return self->pollEvent_.async_wait(ct);
				}, deadline);
				if(!raised)
					co_return protocols::fs::Error::wouldBlock;
			}
		}

		auto sock = self->pendingConnections_.front();
		self->removeChild_(sock.get());
		sock->listener_ = {};

		auto [localCtrl, remoteCtrl] = helix::createStream();
		auto [localPt, remotePt] = helix::createStream();

		async::detach(
			serveLanes(std::move(localCtrl), std::move(localPt), std::move(sock))
		);

		co_return std::make_pair(std::move(remoteCtrl), std::move(remotePt));
	}

	static async::result<protocols::fs::ReadResult> read(void *object, helix_ng::CredentialsView creds,
			void *data, size_t size, async::cancellation_token) {
		auto result = co_await recvMsg(object, creds, 0, data, size, nullptr, 0, {});
		if(auto e = std::get_if<protocols::fs::Error>(&result); e)
			co_return std::unexpected{*e};
		co_return std::get<protocols::fs::RecvData>(result).dataLength;
	}

	static async::result<frg::expected<protocols::fs::Error, size_t>> write(void *object, helix_ng::CredentialsView creds,
			const void *data, size_t size) {
		co_return co_await sendMsg(object, creds, 0, const_cast<void *>(data), size, nullptr, 0, {}, {});
	}

	static async::result<protocols::fs::RecvResult> recvMsg(void *object,
			helix_ng::CredentialsView creds, uint32_t flags,
			void *data, size_t size,
			void *addrPtr, size_t addrLength, size_t max_ctrl_len) {
		(void) creds;
		(void) max_ctrl_len;

		auto self = static_cast<Tcp4Socket *>(object);
		auto p = reinterpret_cast<char *>(data);

		if(flags & ~(MSG_PEEK | MSG_DONTWAIT))
			std::cout << "\e[31m" "netserver/tcp: Encountered unexpected recvMsg() flags: "
					<< flags << "\e[39m" << std::endl;

		auto deadline = helix::deadlineAfter(self->recvTimeoutNs_);
		size_t progress = 0;
		while(progress < size) {
			size_t available = self->receive_.readable();
			if(!available) {
				if(progress)
					break;
				if(self->pendingError_ != Error::none)
					co_return self->consumeError_();
				if(self->receive_.finished() || self->localClosed_ || self->connectState_ == ConnectState::closed)
					break;
				if(!self->synchronized_())
					co_return Error::notConnected;
				if(self->nonBlock_ || flags & MSG_DONTWAIT)
					co_return protocols::fs::Error::wouldBlock;
				auto raised = co_await helix::withTimeout([&](async::cancellation_token ct) {
					return self->inEvent_.async_wait(ct);
				}, deadline);
				if(!raised)
					co_return protocols::fs::Error::wouldBlock;
				continue;
			}
			size_t chunk = std::min(available, size - progress);
			self->receive_.read({p + progress, chunk}, flags & MSG_PEEK);
			progress += chunk;
			if(flags & MSG_PEEK)
				break;
			self->kickEmitter_();
		}

		struct sockaddr_in sa;
		memset(&sa, 0, sizeof(struct sockaddr_in));
		sa.sin_port = arch::to_endian<arch::big_endian, uint16_t>(self->remoteEp_.port);
		sa.sin_addr.s_addr = arch::to_endian<arch::big_endian, uint32_t>(self->remoteEp_.ipAddress);
		if(addrLength)
			memcpy(addrPtr, &sa, std::min(sizeof(struct sockaddr_in), addrLength));

		co_return protocols::fs::RecvData{{}, progress, sizeof(struct sockaddr_in), 0};
	}

	static async::result<frg::expected<protocols::fs::Error, size_t>> sendMsg(void *object,
			helix_ng::CredentialsView creds, uint32_t flags,
			void *data, size_t size,
			void *addrPtr, size_t addrSize,
			std::vector<uint32_t> fds, struct ucred) {
		(void) creds;
		(void) addrPtr;
		(void) addrSize;
		(void) fds;

		auto self = static_cast<Tcp4Socket *>(object);
		auto p = reinterpret_cast<char *>(data);

		auto deadline = helix::deadlineAfter(self->sendTimeoutNs_);
		size_t progress = 0;
		do {
			if(self->pendingError_ != Error::none || self->connectState_ != ConnectState::connected) {
				if(progress)
					break;
				if(self->pendingError_ != Error::none)
					co_return self->consumeError_();
				if(self->connectState_ == ConnectState::closed || self->localClosed_)
					co_return Error::brokenPipe;
				co_return Error::notConnected;
			}
			if(!size)
				break;
			size_t space = self->sendRing_.spaceForEnqueue();
			if(!space) {
				bool settled = false;
				if(!self->nonBlock_ && !(flags & MSG_DONTWAIT))
					settled = co_await helix::withTimeout([&](async::cancellation_token ct) {
						return self->settleEvent_.async_wait(ct);
					}, deadline);
				if(!settled) {
					if(progress)
						break;
					co_return protocols::fs::Error::wouldBlock;
				}
				continue;
			}
			size_t chunk = std::min(space, size - progress);
			self->sendRing_.enqueue(p + progress, chunk);
			progress += chunk;
			self->refreshTimers_(helix::getClock());
			self->kickEmitter_();
		} while(progress < size);

		co_return progress;
	}

	static async::result<frg::expected<protocols::fs::Error, protocols::fs::PollWaitResult>>
	pollWait(void *object, uint64_t pastSeq, int mask, async::cancellation_token cancellation) {
		auto self = static_cast<Tcp4Socket *>(object);
		int edges = 0;

		// TODO: Return an error in this case.
		if(pastSeq > self->currentSeq_) {
			std::cout << "netserver: Illegal pastSeq in TCP poll()" << std::endl;
			pastSeq = self->currentSeq_;
		}

		while(true) {
			edges = 0;
			if(self->inSeq_ > pastSeq || self->listenSeq_ > pastSeq)
				edges |= EPOLLIN | EPOLLRDNORM;
			if(self->outSeq_ > pastSeq)
				edges |= EPOLLOUT | EPOLLWRNORM;
			if(self->hupSeq_ > pastSeq)
				edges |= self->hangupEvents_();
			if(self->errorSeq_ > pastSeq && self->pendingError_ != Error::none)
				edges |= EPOLLERR;

			if (edges & mask)
				break;

			if (!co_await self->pollEvent_.async_wait(cancellation))
				break;
		}

		co_return protocols::fs::PollWaitResult{self->currentSeq_, edges & mask};
	}

	static async::result<frg::expected<protocols::fs::Error, protocols::fs::PollStatusResult>>
	pollStatus(void *object) {
		auto self = static_cast<Tcp4Socket *>(object);

		int active = 0;
		if(self->receive_.readable() || self->receive_.finished()
				|| !self->pendingConnections_.empty() || self->connectState_ == ConnectState::closed)
			active |= EPOLLIN | EPOLLRDNORM;
		if(self->connectState_ == ConnectState::connected && self->sendRing_.spaceForEnqueue())
			active |= EPOLLOUT | EPOLLWRNORM;
		active |= self->hangupEvents_();
		if(self->pendingError_ != Error::none)
			active |= EPOLLERR;

		co_return protocols::fs::PollStatusResult{self->currentSeq_, active};
	}

	static async::result<void> setFileFlags(void *object, int flags) {
		auto self = static_cast<Tcp4Socket *>(object);
		// Like on Linux, F_SETFL ignores the access mode (F_GETFL reports it), such that
		// fcntl(F_SETFL, fcntl(F_GETFL) | O_NONBLOCK) works.
		flags &= ~O_ACCMODE;
		std::cout << "posix: setFileFlags on tcp socket only supports O_NONBLOCK" << std::endl;
		if(flags & ~O_NONBLOCK) {
			std::cout << "posix: setFileFlags on tcp socket called with unknown flags" << std::endl;
			co_return;
		}
		if(flags & O_NONBLOCK)
			self->nonBlock_ = true;
		else
			self->nonBlock_ = false;
		co_return;
	}

	static async::result<int> getFileFlags(void *object) {
		auto self = static_cast<Tcp4Socket *>(object);
		if(self->nonBlock_)
			co_return O_NONBLOCK;
		co_return 0;
	}

	static async::result<frg::expected<protocols::fs::Error>> setSocketOption(void *object,
		int layer, int number, std::vector<char> optbuf) {
		auto self = static_cast<Tcp4Socket *>(object);

		if(layer == SOL_SOCKET && number == SO_BINDTODEVICE) {
			std::string ifname{optbuf.data(), optbuf.size()};

			if(ifname.empty()) {
				self->boundInterface_ = {};
			} else {
				auto nic = nic::Link::byName(ifname);

				if(!nic)
					co_return protocols::fs::Error::illegalArguments;

				self->boundInterface_ = nic;
				co_return {};
			}
		} else if(layer == SOL_SOCKET && (number == SO_RCVTIMEO || number == SO_SNDTIMEO)) {
			auto timeout = parseTimeout(optbuf);
			if(!timeout)
				co_return timeout.error();
			if(number == SO_RCVTIMEO)
				self->recvTimeoutNs_ = *timeout;
			else
				self->sendTimeoutNs_ = *timeout;
			co_return {};
		}

		std::cout << std::format("netserver: unhandled TCP socket setsockopt layer {} number {}\n",
			layer, number);

		co_return protocols::fs::Error::invalidProtocolOption;
	}

	static async::result<frg::expected<protocols::fs::Error>> getSocketOption(void *object,
	helix_ng::CredentialsView, int layer, int number, std::vector<char> &optbuf) {
		auto self = static_cast<Tcp4Socket *>(object);

		if(layer == SOL_SOCKET && number == SO_TYPE) {
			auto type_ = SOCK_STREAM;
			optbuf.resize(std::min(optbuf.size(), sizeof(type_)));
			memcpy(optbuf.data(), &type_, optbuf.size());
		} else if(layer == SOL_SOCKET && number == SO_ERROR) {
			int error = 0;
			switch(self->consumeError_()) {
				case Error::connectionReset: error = ECONNRESET; break;
				case Error::timedOut: error = ETIMEDOUT; break;
				default: break;
			}
			optbuf.resize(std::min(optbuf.size(), sizeof(error)));
			if(!optbuf.empty())
				memcpy(optbuf.data(), &error, optbuf.size());
		} else if(layer == SOL_SOCKET && number == SO_BINDTODEVICE) {
			size_t size = self->boundInterface_ ? self->boundInterface_->name().size() : 0;
			optbuf.resize(size);
			if (size)
				memcpy(optbuf.data(), self->boundInterface_->name().data(), size);
		} else {
			std::cout << std::format("netserver: unhandled TCP socket getsockopt layer {} number {}\n",
				layer, number);
			co_return protocols::fs::Error::invalidProtocolOption;
		}

		co_return {};
	}

	constexpr static protocols::fs::FileOperations ops {
		.read = &read,
		.write = &write,
		.ioctl = &ioctl,
		.pollWait = &pollWait,
		.pollStatus = &pollStatus,
		.bind = &bind,
		.listen = &listen,
		.connect = &connect,
		.accept = &accept,
		.sockname = &sockname,
		.getFileFlags = &getFileFlags,
		.setFileFlags = &setFileFlags,
		.recvMsg = &recvMsg,
		.sendMsg = &sendMsg,
		.peername = &peername,
		.setSocketOption = &setSocketOption,
		.getSocketOption = &getSocketOption,
	};

	bool bindAvailable(uint32_t ipAddress, bool unique) {
		static std::uniform_int_distribution<uint16_t> dist {
			32768, 60999
		};
		auto number = dist(globalPrng);
		auto range = dist.b() - dist.a();
		auto self = holder_.lock();
		for (int i = 0; i < range; i++) {
			uint16_t port = dist.a() + ((number + i) % range);
			if (parent_->tryBind(self, unique, { ipAddress, port }))
				return true;
		}
		return false;
	}

private:
	friend struct Tcp4;

	enum class ConnectState {
		none,
		sendSyn,
		sendSynAck,
		connected,
		closing,
		timeWait,
		closed,
	};

	enum class SegmentKind { data, syn, fin };

	struct Outstanding {
		uint32_t end;
		SegmentKind kind;
		bool timedOut = false;
	};

	struct ConnectAttempt {
		std::optional<Error> result;
	};

	bool synchronized_() const {
		return connectState_ == ConnectState::connected || connectState_ == ConnectState::closing;
	}

	bool handshaking_() const {
		return connectState_ == ConnectState::sendSyn || connectState_ == ConnectState::sendSynAck;
	}

	int hangupEvents_() const {
		if(connectState_ == ConnectState::closed)
			return EPOLLHUP | EPOLLRDHUP;
		return receive_.finished() ? EPOLLRDHUP : 0;
	}

	Error consumeError_() { return std::exchange(pendingError_, Error::none); }

	uint32_t flightData_() const {
		return !outstanding_.empty() && outstanding_.front().kind == SegmentKind::data
				? sendNext_ - sendUna_ : 0;
	}

	uint32_t peerWindow_() const {
		return tcp::before(sendUna_, windowEnd_) ? windowEnd_ - sendUna_ : 0;
	}

	bool pendingSend_() {
		return !outstanding_.empty() || sendRing_.availableToDequeue()
				|| (connectState_ == ConnectState::closing && !finSent_);
	}

	void startHandshake_(ConnectState, TcpEndpoint, uint16_t);
	void completeHandshake_(const TcpPacket &, uint64_t);
	void handleInPacket_(const TcpPacket &);
	void handleListening_(const TcpPacket &);
	void handleSynchronized_(const TcpPacket &, uint64_t);
	void processAck_(const TcpPacket &, uint64_t);
	void acknowledge_(uint32_t ack, uint64_t now);

	void removeChild_(Tcp4Socket *child);
	void terminate_(Error error = Error::none, bool resetPeer = false);
	void finishClose_(uint64_t now);
	void forceAck_(bool challenge, uint64_t now);

	std::optional<std::vector<char>> buildSegment_(uint64_t now, const Ip4TargetInfo *target);
	void kickEmitter_();
	async::result<void> runEmitter_(smarter::shared_ptr<Tcp4Socket>);

	void refreshTimers_(uint64_t now);
	void updateTimer_();
	async::result<void> runTimer_(smarter::shared_ptr<Tcp4Socket>,
			std::shared_ptr<async::cancellation_event>, uint64_t deadline);
	void onTimer_(uint64_t now);

	Tcp4 *parent_;
	bool nonBlock_;
	TcpEndpoint remoteEp_;
	TcpEndpoint localEp_;
	bool bound_ = false;
	std::optional<TcpEndpoint> originalBind_;
	smarter::weak_ptr<Tcp4Socket> holder_;
	smarter::weak_ptr<Tcp4Socket> listener_;
	std::vector<smarter::shared_ptr<Tcp4Socket>> children_;
	std::vector<smarter::shared_ptr<Tcp4Socket>> pendingConnections_;
	std::shared_ptr<ConnectAttempt> connectAttempt_;

	ConnectState connectState_ = ConnectState::none;
	Error pendingError_ = Error::none;
	bool localClosed_ = false;
	bool listening_ = false;
	bool finSent_ = false;
	bool finAcked_ = false;
	bool activeClose_ = false;
	bool handshakeLoss_ = false;
	uint16_t localMss_ = maxPayload;
	uint16_t peerMss_ = defaultMss;

	// sendUna_ is the first unacknowledged sequence; sendNext_ is next to send.
	// windowEnd_ is the right edge of the peer's advertised window.
	uint32_t sendUna_ = 0;
	uint32_t sendNext_ = 0;
	uint32_t initialSendSequence_ = 0;
	uint32_t initialReceiveSequence_ = 0;
	uint32_t windowEnd_ = 0;
	uint32_t windowSeq_ = 0;
	uint32_t windowAck_ = 0;
	uint16_t lastAckWindow_ = 0;
	uint32_t sentAck_ = 0;
	uint32_t announcedEnd_ = 0;
	unsigned forcedAcks_ = 0;
	uint64_t nextChallengeAck_ = 0;

	tcp::ReceiveBuffer receive_;
	// Keep sent bytes until ACKed; outstanding_ records the ends of sent segments.
	RingBuffer sendRing_;
	std::deque<Outstanding> outstanding_;
	tcp::RetransmissionTimeout rto_;
	tcp::NewReno congestion_;
	std::optional<uint64_t> lastDataSent_;
	bool retransmit_ = false;
	unsigned limitedCredits_ = 0;
	bool probePending_ = false;
	std::optional<uint32_t> probeByte_;
	uint64_t probeInterval_ = 0;
	std::optional<uint64_t> retryAt_;
	std::optional<uint64_t> probeAt_;
	std::optional<uint64_t> probeAbortAt_;
	std::optional<uint64_t> abortAt_;
	std::optional<uint64_t> closeAt_;
	std::optional<uint64_t> timerAt_;
	std::shared_ptr<async::cancellation_event> timerCancellation_;
	std::shared_ptr<async::cancellation_event> sendCancellation_;

	async::recurring_event inEvent_;
	async::recurring_event settleEvent_;
	bool emitterActive_ = false;

	uint64_t currentSeq_ = 1;
	uint64_t inSeq_ = 0;
	uint64_t outSeq_ = 0;
	uint64_t hupSeq_ = 0;
	uint64_t errorSeq_ = 0;
	uint64_t listenSeq_ = 0;
	async::recurring_event pollEvent_;

	std::shared_ptr<nic::Link> boundInterface_;
	std::optional<uint64_t> recvTimeoutNs_;
	std::optional<uint64_t> sendTimeoutNs_;
};

void Tcp4Socket::startHandshake_(ConnectState state, TcpEndpoint remote, uint16_t mss) {
	remoteEp_ = remote;
	connectState_ = state;
	initialSendSequence_ = globalPrng();
	sendUna_ = sendNext_ = initialSendSequence_;
	localMss_ = mss;
	handshakeLoss_ = false;
	pendingError_ = Error::none;
	rto_ = {};
	congestion_ = {};
	sendCancellation_ = std::make_shared<async::cancellation_event>();
	abortAt_ = helix::getClock() + handshakeTimeout;
	updateTimer_();
	kickEmitter_();
}

void Tcp4Socket::removeChild_(Tcp4Socket *child) {
	auto isChild = [&](auto &entry) { return entry.get() == child; };
	std::erase_if(children_, isChild);
	std::erase_if(pendingConnections_, isChild);
}

void Tcp4Socket::terminate_(Error error, bool resetPeer) {
	auto self = holder_.lock();
	if(connectState_ == ConnectState::closed)
		return;

	bool failedOpen = connectState_ == ConnectState::sendSyn;
	bool retryable = failedOpen && !localClosed_;
	bool reportError = synchronized_() && error != Error::none && !localClosed_ && !listener_.lock();
	auto local = localEp_;
	auto remote = remoteEp_;
	auto firstUnacknowledged = sendUna_;
	auto resetSequence = sendNext_;
	bool halfOpen = connectState_ == ConnectState::sendSynAck;
	auto resetAck = initialReceiveSequence_ + 1;

	connectState_ = retryable ? ConnectState::none : ConnectState::closed;
	listening_ = false;
	pendingError_ = reportError ? error : Error::none;
	if(auto listener = listener_.lock()) {
		listener->removeChild_(this);
		listener_ = {};
	}
	if(connectAttempt_) {
		connectAttempt_->result = error;
		connectAttempt_.reset();
	}
	if(retryable && originalBind_) {
		if(localEp_.ipAddress != originalBind_->ipAddress)
			parent_->rebind(this, *originalBind_);
	} else {
		parent_->unbind(this);
		if(retryable)
			localEp_ = {};
	}
	originalBind_.reset();

	sendRing_.dequeueAdvance(sendRing_.availableToDequeue());
	receive_.discardGaps();
	outstanding_.clear();
	rto_.discardSample();
	retryAt_.reset();
	probeAt_.reset();
	probeAbortAt_.reset();
	probeByte_.reset();
	abortAt_.reset();
	closeAt_.reset();
	lastDataSent_.reset();
	retransmit_ = probePending_ = false;
	forcedAcks_ = limitedCredits_ = 0;
	auto cancelSend = std::exchange(sendCancellation_, {});
	updateTimer_();

	if(!retryable) {
		hupSeq_ = inSeq_ = ++currentSeq_;
		if(reportError)
			errorSeq_ = currentSeq_;
	}

	if(cancelSend)
		cancelSend->cancel();
	if(resetPeer) {
		// The peer may have rejected a zero-window probe or accepted all sent data.
		// Either sequence can be its exact RCV.NXT when we abort.
		if(!halfOpen && firstUnacknowledged != resetSequence)
			async::detach(sendReset(local, remote,
					{.seq = firstUnacknowledged, .rst = true}, boundInterface_));
		// A half-open child must acknowledge the peer's SYN for its reset to be accepted.
		async::detach(sendReset(local, remote,
				{.seq = resetSequence, .ack = halfOpen ? resetAck : 0,
					.rst = true, .ackFlag = halfOpen}, boundInterface_));
	}
	inEvent_.raise();
	settleEvent_.raise();
	pollEvent_.raise();
}

void Tcp4Socket::disconnect() {
	if(localClosed_)
		return;
	localClosed_ = true;
	auto children = std::move(children_);
	for(auto &child : children)
		child->terminate_(Error::none, child->sendNext_ != child->initialSendSequence_);
	if(!synchronized_()) {
		if(connectState_ != ConnectState::timeWait)
			terminate_(Error::interrupted);
		return;
	}
	if(receive_.hasData()) {
		terminate_(Error::none, true);
		return;
	}
	connectState_ = ConnectState::closing;
	auto now = helix::getClock();
	closeAt_ = now + deliveryTimeout;
	refreshTimers_(now);
	inEvent_.raise();
	settleEvent_.raise();
	kickEmitter_();
}

void Tcp4Socket::finishClose_(uint64_t now) {
	if(!finAcked_)
		return;
	if(!receive_.finished()) {
		if(closeAt_ && *closeAt_ > now + finishTimeout)
			closeAt_ = now + finishTimeout;
		return;
	}
	if(!activeClose_) {
		terminate_();
		return;
	}
	connectState_ = ConnectState::timeWait;
	closeAt_ = now + finishTimeout;
}

void Tcp4Socket::refreshTimers_(uint64_t now) {
	if(synchronized_()) {
		if(pendingSend_() && !peerWindow_()) {
			// Persist probes replace retransmission timeouts while the window is closed.
			if(!probeAbortAt_) {
				probeInterval_ = rto_.value();
				probeAt_ = now + probeInterval_;
				probeAbortAt_ = now + deliveryTimeout;
			}
			retryAt_.reset();
			abortAt_.reset();
			retransmit_ = false;
			limitedCredits_ = 0;
		} else {
			if(probeAbortAt_ && !outstanding_.empty())
				retransmit_ = true;
			probeAt_.reset();
			probeAbortAt_.reset();
			probePending_ = false;
			if(!pendingSend_())
				abortAt_.reset();
			else if(!abortAt_)
				abortAt_ = now + deliveryTimeout;

			if(outstanding_.empty())
				retryAt_.reset();
			else if(!retryAt_ && !retransmit_)
				retryAt_ = now + rto_.value();
		}
	} else if(connectState_ == ConnectState::timeWait) {
		retryAt_.reset();
		probeAt_.reset();
		probeAbortAt_.reset();
		abortAt_.reset();
	}
	updateTimer_();
}

void Tcp4Socket::updateTimer_() {
	std::optional<uint64_t> next;
	for(auto at : {retryAt_, probeAt_, abortAt_, probeAbortAt_, closeAt_})
		if(at && (!next || *at < *next))
			next = at;
	if(next == timerAt_)
		return;
	auto old = std::exchange(timerCancellation_, {});
	timerAt_ = next;
	if(next) {
		timerCancellation_ = std::make_shared<async::cancellation_event>();
		async::detach(runTimer_(holder_.lock(), timerCancellation_, *next));
	}
	if(old)
		old->cancel();
}

async::result<void> Tcp4Socket::runTimer_(smarter::shared_ptr<Tcp4Socket>,
		std::shared_ptr<async::cancellation_event> cancellation, uint64_t deadline) {
	if(!co_await helix::sleepUntil(deadline, *cancellation) || cancellation != timerCancellation_)
		co_return;
	timerAt_.reset();
	timerCancellation_.reset();
	onTimer_(helix::getClock());
}

void Tcp4Socket::onTimer_(uint64_t now) {
	if((abortAt_ && now >= *abortAt_) || (probeAbortAt_ && now >= *probeAbortAt_)) {
		terminate_(Error::timedOut);
		return;
	}
	if(closeAt_ && now >= *closeAt_) {
		terminate_();
		return;
	}
	if(retryAt_ && now >= *retryAt_) {
		assert(!outstanding_.empty());
		auto &oldest = outstanding_.front();
		if(oldest.kind == SegmentKind::syn)
			handshakeLoss_ = true;
		if(synchronized_())
			congestion_.timeout(sendNext_, flightData_(), !oldest.timedOut);
		oldest.timedOut = true;
		rto_.discardSample();
		rto_.backOff();
		retryAt_.reset();
		limitedCredits_ = 0;
		retransmit_ = true;
	}
	if(probeAt_ && now >= *probeAt_) {
		probeInterval_ = std::min(2 * probeInterval_, tcp::RetransmissionTimeout::maximum);
		probeAt_ = now + probeInterval_;
		probePending_ = true;
	}
	updateTimer_();
	kickEmitter_();
}

void Tcp4Socket::forceAck_(bool challenge, uint64_t now) {
	if(challenge) {
		if(now < nextChallengeAck_)
			return;
		nextChallengeAck_ = now + tcp::second / 10;
	}
	forcedAcks_ = std::min(forcedAcks_ + 1, 3u);
}

std::optional<std::vector<char>> Tcp4Socket::buildSegment_(uint64_t now, const Ip4TargetInfo *target) {
	Segment segment{.seq = sendNext_};
	size_t bytes = 0;
	size_t offset = 0;
	bool isRetry = false;
	bool isProbe = false;
	bool limited = false;
	// New SYN, data, or FIN advances sendNext_; retransmissions do not.
	std::optional<SegmentKind> newSpace;

	if(handshaking_()) {
		if(!outstanding_.empty() && !retransmit_)
			return std::nullopt;
		if(!outstanding_.empty()) {
			segment.seq = sendUna_;
			isRetry = true;
			handshakeLoss_ = true;
		} else {
			if(target)
				localMss_ = localMss(*target);
			newSpace = SegmentKind::syn;
		}
		segment.syn = true;
		segment.mss = localMss_;
		segment.ackFlag = connectState_ == ConnectState::sendSynAck;
		segment.window = tcp::ReceiveBuffer::capacity;
	} else if(synchronized_() || connectState_ == ConnectState::timeWait) {
		segment.ackFlag = true;
		segment.window = receive_.window();
		auto flight = flightData_();
		auto mss = congestion_.mss();
		if(target)
			mss = std::min<uint32_t>(mss, localMss(*target));

		if(forcedAcks_) {
			// A duplicate or challenge acknowledgment needs the current SND.NXT.
		} else if(probePending_) {
			probePending_ = false;
			isProbe = true;
			if(!outstanding_.empty()) {
				segment.seq = sendUna_;
				if(outstanding_.front().kind == SegmentKind::fin)
					segment.fin = true;
				else
					bytes = 1;
				isRetry = true;
			} else if(sendRing_.availableToDequeue()) {
				newSpace = SegmentKind::data;
				probeByte_ = sendNext_;
				bytes = 1;
			} else {
				// FIN is queued behind a closed window. An old sequence elicits an ACK.
				segment.seq = sendNext_ - 1;
			}
		} else if(retransmit_ && !outstanding_.empty()) {
			auto &first = outstanding_.front();
			segment.seq = sendUna_;
			segment.fin = first.kind == SegmentKind::fin;
			if(!segment.fin)
				bytes = std::min({first.end - sendUna_, mss, peerWindow_()});
			isRetry = true;
		} else if(synchronized_()) {
			if(!flight && lastDataSent_ && now - *lastDataSent_ >= rto_.value())
				congestion_.restartAfterIdle();
			auto queued = sendRing_.availableToDequeue();
			if(queued > flight && peerWindow_() > flight) {
				auto allowed = congestion_.window();
				if(limitedCredits_)
					allowed = congestion_.limitedWindow();
				if(allowed > flight) {
					offset = flight;
					bytes = std::min({queued - flight, size_t{peerWindow_() - flight},
							size_t{allowed - flight}, size_t{mss}});
					limited = limitedCredits_ != 0;
					newSpace = SegmentKind::data;
				}
			} else if(connectState_ == ConnectState::closing && !queued && !finSent_ && peerWindow_()) {
				segment.fin = true;
				finSent_ = true;
				activeClose_ = !receive_.finished();
				newSpace = SegmentKind::fin;
			}
		}
		bool windowChanged = tcp::before(announcedEnd_, receive_.next() + segment.window);
		if(!newSpace && !isRetry && !isProbe && !forcedAcks_
				&& !windowChanged && sentAck_ == receive_.next())
			return std::nullopt;
	} else {
		return std::nullopt;
	}

	if(segment.ackFlag) {
		segment.ack = receive_.next();
		if(forcedAcks_)
			--forcedAcks_;
		sentAck_ = segment.ack;
		announcedEnd_ = segment.ack + segment.window;
	}

	auto buf = encodeSegment(localEp_, remoteEp_, segment, bytes);
	if(bytes)
		sendRing_.dequeueLookahead(offset, buf.data() + sizeof(TcpHeader), bytes);
	checksumSegment(buf, localEp_, remoteEp_);

	if(isRetry) {
		retransmit_ = false;
		rto_.retransmitted(segment.seq);
	}
	if(newSpace) {
		sendNext_ += *newSpace == SegmentKind::data ? bytes : 1;
		outstanding_.push_back({sendNext_, *newSpace});
		if(target && !isProbe)
			rto_.sent(sendNext_, now);
	}
	if(bytes && !isProbe)
		lastDataSent_ = now;
	if(limited) {
		--limitedCredits_;
		congestion_.sentLimited(bytes);
	}
	if((newSpace || isRetry) && !isProbe && !retryAt_)
		retryAt_ = now + rto_.value();
	updateTimer_();
	return buf;
}

void Tcp4Socket::kickEmitter_() {
	if(emitterActive_ || !sendCancellation_)
		return;
	emitterActive_ = true;
	async::detach(runEmitter_(holder_.lock()));
}

async::result<void> Tcp4Socket::runEmitter_(smarter::shared_ptr<Tcp4Socket>) {
	while(auto cancellation = sendCancellation_) {
		auto target = co_await ip4().targetByRemote(remoteEp_.ipAddress, boundInterface_);
		if(cancellation != sendCancellation_)
			continue;
		auto buf = buildSegment_(helix::getClock(), target ? &*target : nullptr);
		if(!buf)
			break;
		if(target) {
			target->source = localEp_.ipAddress;
			auto error = co_await ip4().sendFrame(std::move(*target), buf->data(), buf->size(),
					static_cast<uint16_t>(IpProto::tcp), *cancellation);
			if(error != Error::none && cancellation == sendCancellation_)
				rto_.discardSample();
		}
	}
	emitterActive_ = false;
}

void Tcp4Socket::acknowledge_(uint32_t ack, uint64_t now) {
	rto_.acknowledged(ack, now);

	if(flightData_())
		sendRing_.dequeueAdvance(ack - sendUna_);
	sendUna_ = ack;
	while(!outstanding_.empty() && !tcp::before(ack, outstanding_.front().end)) {
		if(outstanding_.front().kind == SegmentKind::fin)
			finAcked_ = true;
		outstanding_.pop_front();
	}
}

void Tcp4Socket::completeHandshake_(const TcpPacket &packet, uint64_t now) {
	bool active = connectState_ == ConnectState::sendSyn;
	if(active) {
		initialReceiveSequence_ = packet.header.seqNumber.load();
		receive_.reset(initialReceiveSequence_ + 1);
		sentAck_ = initialReceiveSequence_;
		announcedEnd_ = receive_.next() + tcp::ReceiveBuffer::capacity;
		peerMss_ = packet.mss();
	}
	acknowledge_(packet.header.ackNumber.load(), now);
	windowSeq_ = packet.header.seqNumber.load();
	windowAck_ = sendUna_;
	lastAckWindow_ = packet.header.window.load();
	windowEnd_ = sendUna_ + lastAckWindow_;
	if(handshakeLoss_)
		rto_.afterHandshakeLoss();
	congestion_.initialize(std::min(localMss_, peerMss_), handshakeLoss_);
	retryAt_.reset();
	abortAt_.reset();
	retransmit_ = false;
	connectState_ = ConnectState::connected;
	outSeq_ = ++currentSeq_;
	if(connectAttempt_) {
		connectAttempt_->result = Error::none;
		connectAttempt_.reset();
	}
	updateTimer_();
}

void Tcp4Socket::processAck_(const TcpPacket &packet, uint64_t now) {
	auto ack = packet.header.ackNumber.load();
	auto seq = packet.header.seqNumber.load();
	auto window = packet.header.window.load();
	if(tcp::before(ack, sendUna_))
		return;

	bool sameWindow = window == lastAckWindow_;
	lastAckWindow_ = window;
	auto oldPeerWindow = peerWindow_();
	// Ignore stale window advertisements using the peer's sequence and ACK numbers.
	if(tcp::before(windowSeq_, seq) || (seq == windowSeq_ && !tcp::before(ack, windowAck_))) {
		windowSeq_ = seq;
		windowAck_ = ack;
		windowEnd_ = ack + window;
	}

	if(probeAbortAt_)
		probeAbortAt_ = now + deliveryTimeout;

	if(ack == sendUna_) {
		if(!peerWindow_() || !oldPeerWindow || !sameWindow) {
			limitedCredits_ = 0;
			congestion_.windowChanged();
		} else if(flightData_() && !packet.sequenceLength()) {
			auto action = congestion_.duplicateAck(sendUna_, sendNext_, flightData_(), outstanding_.size());
			if(action == tcp::NewReno::Action::limitedTransmit)
				++limitedCredits_;
			if(action == tcp::NewReno::Action::retransmit) {
				limitedCredits_ = 0;
				retransmit_ = true;
			}
		}
		return;
	}

	auto dataAcked = flightData_() ? ack - sendUna_ : 0;
	bool wasFull = !sendRing_.spaceForEnqueue();
	if(probeByte_ && tcp::before(*probeByte_, ack)) {
		--dataAcked;
		probeByte_.reset();
	}
	acknowledge_(ack, now);
	abortAt_ = now + deliveryTimeout;
	retransmit_ = false;
	limitedCredits_ = 0;

	bool restart = true;
	if(dataAcked) {
		auto action = congestion_.acknowledge(ack, dataAcked, flightData_());
		if(action == tcp::NewReno::Action::retransmit) {
			retransmit_ = true;
			restart = congestion_.firstPartialAck();
			congestion_.finishPartialAck();
		}
	}
	if(outstanding_.empty())
		retryAt_.reset();
	else if(restart)
		retryAt_ = now + rto_.value();
	if(wasFull && sendRing_.spaceForEnqueue() && connectState_ == ConnectState::connected)
		outSeq_ = ++currentSeq_;
}

void Tcp4Socket::handleListening_(const TcpPacket &packet) {
	if(packet.rst())
		return;
	if(packet.ack()) {
		replyReset(packet, boundInterface_);
		return;
	}
	if(!packet.syn() || packet.fin() || children_.size() >= maxPendingConnections)
		return;

	auto child = makeSocket(parent_, false);
	TcpEndpoint local{packet.packet->header.destination, localEp_.port};
	TcpEndpoint remote{packet.packet->header.source, packet.header.srcPort.load()};
	if(!parent_->tryBind(child, false, local))
		return;
	child->listener_ = holder_;
	child->boundInterface_ = boundInterface_;
	child->initialReceiveSequence_ = packet.header.seqNumber.load();
	child->receive_.reset(child->initialReceiveSequence_ + 1);
	child->peerMss_ = packet.mss();
	children_.push_back(child);
	child->startHandshake_(ConnectState::sendSynAck, remote, maxPayload);
}

void Tcp4Socket::handleSynchronized_(const TcpPacket &packet, uint64_t now) {
	auto seq = packet.header.seqNumber.load();
	if(packet.syn()) {
		// If the third handshake segment was lost, regenerate the ACK.
		bool repeatedSynAck = packet.ack() && seq == initialReceiveSequence_
				&& packet.header.ackNumber.load() == initialSendSequence_ + 1;
		forceAck_(!repeatedSynAck, now);
		kickEmitter_();
		return;
	}
	if(!receive_.accepts(seq, packet.sequenceLength()) && packet.sequenceLength()) {
		forceAck_(false, now);
		kickEmitter_();
		return;
	}
	if(!receive_.accepts(seq, packet.sequenceLength())) {
		// An old ACK-only probe elicits the current window. Unacceptable ACKs are never processed.
		forceAck_(true, now);
		kickEmitter_();
		return;
	}
	if(!packet.ack())
		return;
	auto ack = packet.header.ackNumber.load();
	if(ack - sendUna_ > sendNext_ - sendUna_) {
		forceAck_(true, now);
		kickEmitter_();
		return;
	}

	auto oldReadable = receive_.readable();
	bool hadFin = receive_.finished();
	auto oldNext = receive_.next();
	auto oldUna = sendUna_;
	auto oldPoll = currentSeq_;
	auto payload = packet.payload();
	processAck_(packet, now);
	if(packet.sequenceLength()) {
		if(localClosed_ && payload.size()) {
			terminate_(Error::none, true);
			return;
		}
		receive_.insert(seq, {reinterpret_cast<const char *>(payload.data()), payload.size()}, packet.fin());
		if(receive_.next() != oldNext)
			forcedAcks_ = 0;
		forceAck_(false, now);
	}

	if(receive_.readable() > oldReadable)
		inSeq_ = ++currentSeq_;
	if(!hadFin && receive_.finished())
		hupSeq_ = inSeq_ = ++currentSeq_;
	if(connectState_ == ConnectState::closing)
		finishClose_(now);
	refreshTimers_(now);
	kickEmitter_();

	if(oldReadable < receive_.readable() || hadFin != receive_.finished())
		inEvent_.raise();
	if(sendUna_ != oldUna)
		settleEvent_.raise();
	if(oldPoll != currentSeq_)
		pollEvent_.raise();
}

void Tcp4Socket::handleInPacket_(const TcpPacket &packet) {
	auto now = helix::getClock();
	if(listening_) {
		handleListening_(packet);
		return;
	}

	auto seq = packet.header.seqNumber.load();
	auto ack = packet.header.ackNumber.load();
	if(connectState_ == ConnectState::sendSyn) {
		bool acceptableAck = packet.ack() && !outstanding_.empty() && ack == sendNext_;
		if(packet.rst()) {
			if(acceptableAck)
				terminate_(Error::connectionRefused);
			return;
		}
		if(packet.ack() && !acceptableAck) {
			replyReset(packet, boundInterface_);
			return;
		}
		if(packet.syn() && acceptableAck && !packet.fin()) {
			completeHandshake_(packet, now);
			forceAck_(false, now);
			kickEmitter_();
			settleEvent_.raise();
			pollEvent_.raise();
		}
		return;
	}

	if(connectState_ == ConnectState::timeWait) {
		if(packet.rst())
			return;
		if(packet.fin() && seq + packet.sequenceLength() == receive_.next()) {
			closeAt_ = now + finishTimeout;
			updateTimer_();
			forceAck_(false, now);
			kickEmitter_();
		}
		return;
	}

	if(packet.rst()) {
		// An in-window but nonexact RST gets a challenge ACK.
		if(seq == receive_.next())
			terminate_(Error::connectionReset);
		else if(tcp::inWindow(seq, receive_.next(), receive_.window())) {
			forceAck_(true, now);
			kickEmitter_();
		}
		return;
	}

	if(connectState_ == ConnectState::sendSynAck) {
		if(packet.syn() && !packet.ack() && seq == initialReceiveSequence_) {
			if(!outstanding_.empty())
				retransmit_ = true;
			kickEmitter_();
			return;
		}
		if(!packet.ack() || !receive_.accepts(seq, packet.sequenceLength()))
			return;
		if(outstanding_.empty() || ack != sendNext_) {
			replyReset(packet, boundInterface_);
			return;
		}
		if(packet.syn() || seq != receive_.next())
			return;
		completeHandshake_(packet, now);
		handleSynchronized_(packet, now);
		if(auto listener = listener_.lock()) {
			listener->pendingConnections_.push_back(holder_.lock());
			listener->listenSeq_ = ++listener->currentSeq_;
			listener->pollEvent_.raise();
		}
		return;
	}

	if(synchronized_())
		handleSynchronized_(packet, now);
}

void Tcp4::feedDatagram(smarter::shared_ptr<const Ip4Packet> packet) {
	TcpPacket tcp;
	if (!tcp.parse(std::move(packet))) {
		return;
	}

	// RFC 1122 4.2.3.10: connections can only ever involve unicast addresses.
	if (ip4().classifyAddress(tcp.packet->header.destination) != Ip4::AddressType::unicast) {
		if (logDiscards)
			std::println("netserver: Discarding TCP segment addressed to a broadcast or multicast address");
		return;
	}

	if(debugTcp)
		std::cout << "netserver: Received TCP packet at port " << tcp.header.destPort.load()
				<< " (" << tcp.payload().size() << " bytes)" << std::endl;

	auto link = tcp.packet->link.lock();
	if(!link || !tcp.header.srcPort.load() || !tcp.header.destPort.load())
		return;
	auto matches = [&](const auto &entry) {
		const auto &[endpoint, sock] = entry;
		return (endpoint.ipAddress == tcp.packet->header.destination || endpoint.ipAddress == INADDR_ANY)
				&& (!sock->boundInterface_ || sock->boundInterface_->index() == link->index());
	};

	// Look for a connection before the listener, which may share its local port.
	for (auto it = binds.lower_bound({ 0, tcp.header.destPort.load() });
			it != binds.end() && it->first.port == tcp.header.destPort.load(); it++) {
		auto sock = it->second;

		if (sock->listening_ || sock->connectState_ == Tcp4Socket::ConnectState::none)
			continue;

		if (tcp.packet->header.source != sock->remoteEp_.ipAddress
				|| tcp.header.srcPort.load() != sock->remoteEp_.port)
			continue;

		if (matches(*it)) {
			sock->handleInPacket_(tcp);
			return;
		}
	}

	// Look for listening sockets (and do not care about their remote endpoints).
	for (auto it = binds.lower_bound({ 0, tcp.header.destPort.load() });
			it != binds.end() && it->first.port == tcp.header.destPort.load(); it++) {
		auto sock = it->second;
		if (sock->listening_ && matches(*it)) {
			sock->handleInPacket_(tcp);
			return;
		}
	}
	replyReset(tcp);
}

bool Tcp4::tryBind(smarter::shared_ptr<Tcp4Socket> socket, bool unique, TcpEndpoint wantedEp) {
	if (unique) {
		auto it = binds.lower_bound({0, wantedEp.port});
		for (; it != binds.end() && it->first.port == wantedEp.port; it++) {
			auto existingEp = it->first;
			if (existingEp.ipAddress == INADDR_ANY || wantedEp.ipAddress == INADDR_ANY
					|| existingEp.ipAddress == wantedEp.ipAddress) {
				return false;
			}
		}
	}
	socket->localEp_ = wantedEp;
	socket->bound_ = true;
	binds.emplace(wantedEp, std::move(socket));
	return true;
}

void Tcp4::unbind(Tcp4Socket *socket) {
	if(!socket->bound_)
		return;
	auto [begin, end] = binds.equal_range(socket->localEp_);
	auto it = std::find_if(begin, end, [&](auto &entry) { return entry.second.get() == socket; });
	assert(it != end);
	socket->bound_ = false;
	binds.erase(it);
}

void Tcp4::rebind(Tcp4Socket *socket, TcpEndpoint newEp) {
	auto [begin, end] = binds.equal_range(socket->localEp_);
	auto it = std::find_if(begin, end, [&](auto &entry) { return entry.second.get() == socket; });
	assert(it != end);
	auto node = binds.extract(it);
	node.key() = newEp;
	socket->localEp_ = newEp;
	binds.insert(std::move(node));
}

static async::result<void> serveLanes(
	helix::UniqueLane ctrlLane,
	helix::UniqueLane ptLane,
	smarter::shared_ptr<Tcp4Socket> sock
) {
	co_await async::race_and_cancel(
		[&](async::cancellation_token) {
			return protocols::fs::serveFile(std::move(ctrlLane),
					sock.get(), &Tcp4Socket::ops);
		},
		[&](async::cancellation_token ct) {
			return protocols::fs::servePassthrough(std::move(ptLane),
					sock, &Tcp4Socket::ops, ct);
		}
	);
	sock->disconnect();
}

void Tcp4::serveSocket(int flags, helix::UniqueLane ctrlLane, helix::UniqueLane ptLane) {
	auto sock = Tcp4Socket::makeSocket(this, flags & SOCK_NONBLOCK);
	async::detach(serveLanes(std::move(ctrlLane), std::move(ptLane), std::move(sock)));
}
