#include <cassert>
#include <string_view>

#include "../../../servers/netserver/src/ip/tcp-state.hpp"
#include "testsuite.hpp"

DEFINE_TEST(tcp_rto_estimation, ([] {
	tcp::RetransmissionTimeout rto;
	assert(rto.value() == tcp::second);
	// The cumulative ACK covers the last byte of the sample across sequence wrap.
	rto.sent(1, 100);
	rto.acknowledged(0, tcp::second + 100);
	assert(rto.value() == tcp::second);
	rto.acknowledged(1, tcp::second + 100);
	assert(rto.value() == 3 * tcp::second);

	// An ACK after retransmission is ambiguous and leaves the backed-off RTO intact.
	rto.sent(1001, 2 * tcp::second);
	rto.retransmitted(1);
	rto.backOff();
	rto.acknowledged(1001, 4 * tcp::second);
	assert(rto.value() == 6 * tcp::second);
	rto.sent(2001, 4 * tcp::second);
	rto.acknowledged(2001, 5 * tcp::second);
	assert(rto.value() == 2'500'000'000);
	rto.afterHandshakeLoss();
	assert(rto.value() == 3 * tcp::second);
	for(int i = 0; i < 10; ++i)
		rto.backOff();
	assert(rto.value() == 60 * tcp::second);
}));

DEFINE_TEST(tcp_newreno_recovery, ([] {
	using Action = tcp::NewReno::Action;
	tcp::NewReno cc;
	constexpr uint32_t mss = 1000;
	cc.initialize(mss, false);
	assert(cc.window() == 4 * mss);
	assert(cc.acknowledge(1000, mss, 3000) == Action::none);
	assert(cc.window() == 5 * mss);
	assert(cc.duplicateAck(1000, 6000, 5000, 5) == Action::limitedTransmit);
	cc.sentLimited(mss);
	assert(cc.duplicateAck(1000, 7000, 6000, 6) == Action::limitedTransmit);
	cc.sentLimited(mss);
	assert(cc.duplicateAck(1000, 8000, 7000, 7) == Action::retransmit);
	assert(cc.window() == 5500);
	assert(cc.recovering() && cc.firstPartialAck());
	assert(cc.acknowledge(4000, 3000, 4000) == Action::retransmit);
	assert(cc.window() == 3500 && cc.recovering());
	cc.finishPartialAck();
	assert(!cc.firstPartialAck());
	assert(cc.acknowledge(8000, 4000, 0) == Action::none);
	assert(cc.window() == 2 * mss && !cc.recovering());
	// An ACK immediately past Recover permits a later loss to enter fast recovery.
	assert(cc.duplicateAck(8000, 10000, 2000, 2) == Action::limitedTransmit);
	assert(cc.duplicateAck(8000, 10000, 2000, 2) == Action::limitedTransmit);
	assert(cc.duplicateAck(8000, 10000, 2000, 2) == Action::retransmit);
	cc.timeout(10000, 2000, true);
	assert(cc.window() == mss);
	assert(cc.duplicateAck(8000, 10000, 2000, 2) == Action::limitedTransmit);
	assert(cc.duplicateAck(8000, 10000, 2000, 2) == Action::limitedTransmit);
	assert(cc.duplicateAck(8000, 10000, 2000, 2) == Action::none);
}));

DEFINE_TEST(tcp_receive_reassembly, ([] {
	using namespace std::string_view_literals;
	tcp::ReceiveBuffer buffer;
	constexpr uint32_t first = UINT32_MAX - 2;
	buffer.reset(first);
	assert(buffer.accepts(first + 4, 1));
	buffer.insert(first + 4, "efg"sv, true);
	assert(buffer.readable() == 0 && !buffer.finished());
	assert(buffer.window() == buffer.capacity && buffer.next() == first);
	buffer.insert(first + 2, "cdXX"sv, false);
	assert(buffer.readable() == 0 && buffer.next() == first);
	assert(buffer.accepts(first - 1, 4));
	buffer.insert(first - 1, "_abZ"sv, false);
	assert(buffer.readable() == 7 && buffer.next() == first + 8);
	assert(buffer.finished() && buffer.window() == 0);
	std::array<char, 7> result;
	buffer.read(result, true);
	assert(buffer.readable() == 7);
	assert(std::string_view(result.data(), result.size()) == "abcdefg");
	buffer.read(result, false);
	assert(!buffer.readable());

	buffer.reset(first);
	std::array<char, tcp::ReceiveBuffer::capacity> full{};
	buffer.insert(first, full, false);
	assert(buffer.window() == 0 && !buffer.accepts(buffer.next(), 1));
	assert(buffer.accepts(buffer.next(), 0));
	buffer.read(result, false);
	assert(buffer.window() == result.size() && buffer.accepts(first + buffer.capacity, 1));
}));
