#pragma once

#include <algorithm>
#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

namespace tcp {

constexpr uint64_t second = 1'000'000'000;

// TCP sequence comparisons must work across wraparound; distances stay below 2^31.
constexpr bool before(uint32_t a, uint32_t b) {
	return static_cast<int32_t>(a - b) < 0;
}

constexpr bool inWindow(uint32_t seq, uint32_t next, uint32_t window) {
	return seq - next < window;
}

// Tracks out-of-order data: read_ is next for the application, contiguous_ the first missing byte.
class ReceiveBuffer {
public:
	static constexpr uint32_t capacity = 16 * 1024;

	void reset(uint32_t first) {
		read_ = contiguous_ = first;
		present_.reset();
		fin_.reset();
		finished_ = false;
	}

	uint32_t readable() const { return contiguous_ - read_; }
	uint32_t next() const { return contiguous_ + finished_; }
	uint32_t window() const { return finished_ ? 0 : capacity - readable(); }
	bool finished() const { return finished_; }
	bool hasData() const { return present_.any(); }

	bool accepts(uint32_t seq, uint32_t length) const {
		if (!window())
			return !length && seq == next();
		if (!length)
			return inWindow(seq, next(), window());
		// An overlapping segment may begin before RCV.NXT.
		return before(seq, next() + window()) && before(next(), seq + length);
	}

	void insert(uint32_t seq, std::span<const char> payload, bool fin) {
		if (finished_)
			return;
		uint32_t finSeq = seq + payload.size();
		if (fin && inWindow(finSeq, next(), window()) && (!fin_ || before(finSeq, *fin_))) {
			// A FIN ends the stream, including data previously queued beyond it.
			for (auto at = finSeq; at != next() + window(); ++at)
				present_.reset(index(at));
			fin_ = finSeq;
		}

		if (before(seq, next())) {
			auto skip = std::min<size_t>(next() - seq, payload.size());
			payload = payload.subspan(skip);
			seq += skip;
		}
		uint32_t end = fin_.value_or(next() + window());
		if (before(seq, end)) {
			for (char byte : payload.first(std::min<size_t>(end - seq, payload.size()))) {
				auto pos = index(seq++);
				if (!present_.test(pos)) {
					bytes_[pos] = byte;
					present_.set(pos);
				}
			}
		}

		while (contiguous_ != end && present_.test(index(contiguous_)))
			++contiguous_;
		if (fin_ && contiguous_ == *fin_)
			finished_ = true;
	}

	void read(std::span<char> output, bool peek) {
		auto seq = read_;
		for (auto &byte : output) {
			auto pos = index(seq++);
			byte = bytes_[pos];
			if (!peek)
				present_.reset(pos);
		}
		if (!peek)
			read_ = seq;
	}

	void discardGaps() {
		for (uint32_t i = 0; i < window(); ++i)
			present_.reset(index(next() + i));
		fin_.reset();
	}

private:
	static size_t index(uint32_t seq) { return seq & (capacity - 1); }

	std::array<char, capacity> bytes_;
	std::bitset<capacity> present_;
	uint32_t read_ = 0;
	uint32_t contiguous_ = 0;
	std::optional<uint32_t> fin_;
	bool finished_ = false;
};

class RetransmissionTimeout {
public:
	uint64_t value() const { return timeout_; }

	void sent(uint32_t end, uint64_t now) {
		if (!sample_)
			sample_ = Sample{end, now};
	}

	void retransmitted(uint32_t start) {
		// Karn's algorithm: discard RTT samples for retransmitted data.
		if (sample_ && before(start, sample_->end))
			sample_.reset();
	}

	void acknowledged(uint32_t ack, uint64_t now) {
		if (sample_ && !before(ack, sample_->end)) {
			update(now - sample_->sentAt);
			sample_.reset();
		}
	}

	void discardSample() { sample_.reset(); }
	void backOff() { timeout_ = std::min(2 * timeout_, maximum); }
	void afterHandshakeLoss() { timeout_ = std::max(timeout_, 3 * second); }

	static constexpr uint64_t maximum = 60 * second;

private:
	struct Sample {
		uint32_t end;
		uint64_t sentAt;
	};
	std::optional<Sample> sample_;

	void update(uint64_t rtt) {
		// Bound the input before computing weighted averages in nanoseconds.
		rtt = std::clamp(rtt, uint64_t{1}, maximum);
		if (srtt_) {
			auto deviation = rtt < *srtt_ ? *srtt_ - rtt : rtt - *srtt_;
			variation_ = (3 * variation_ + deviation) / 4;
			srtt_ = (7 * *srtt_ + rtt) / 8;
		} else {
			srtt_ = rtt;
			variation_ = rtt / 2;
		}
		timeout_ = std::clamp(*srtt_ + std::max(uint64_t{1}, 4 * variation_), second, maximum);
	}

	std::optional<uint64_t> srtt_;
	uint64_t variation_ = 0;
	uint64_t timeout_ = second;
};

class NewReno {
public:
	enum class Action { none, limitedTransmit, retransmit };

	void initialize(uint32_t mss, bool handshakeLoss) {
		mss_ = mss;
		initialWindow_ = (handshakeLoss ? 1 : mss > 1095 ? 3 : 4) * mss;
		window_ = initialWindow_;
	}

	uint32_t mss() const { return mss_; }
	uint32_t window() const { return window_; }
	uint32_t limitedWindow() const { return window_ + 2 * mss_; }
	bool recovering() const { return recovering_; }
	bool firstPartialAck() const { return firstPartial_; }

	Action duplicateAck(uint32_t una, uint32_t next, uint32_t flight, uint32_t segments) {
		if (recovering_) {
			if (inflations_ < segments) {
				window_ += mss_;
				++inflations_;
			}
			return Action::none;
		}
		if (duplicates_ >= 3)
			return Action::none;
		if (++duplicates_ < 3)
			return Action::limitedTransmit;
		// Do not enter fast recovery twice for the same flight of data.
		if (recover_ && !before(*recover_, una))
			return Action::none;
		threshold_ = std::max((flight - limitedBytes_) / 2, 2 * mss_);
		window_ = threshold_ + 3 * mss_;
		recover_ = next - 1;
		recovering_ = true;
		firstPartial_ = true;
		inflations_ = 0;
		credit_ = 0;
		return Action::retransmit;
	}

	void sentLimited(uint32_t length) { limitedBytes_ += length; }

	Action acknowledge(uint32_t ack, uint32_t bytes, uint32_t flight) {
		duplicates_ = 0;
		limitedBytes_ = 0;
		if (recovering_) {
			if (before(*recover_, ack)) {
				window_ = std::min(threshold_, std::max(flight, mss_) + mss_);
				recovering_ = false;
				return Action::none;
			}
			// A partial ACK advances the gap but does not end NewReno recovery.
			window_ -= std::min(window_, bytes);
			if (bytes >= mss_)
				window_ += mss_;
			return Action::retransmit;
		}
		if (window_ < threshold_) {
			window_ += std::min(bytes, mss_);
		} else if ((credit_ += bytes) >= window_) {
			credit_ -= window_;
			window_ += mss_;
		}
		return Action::none;
	}

	void finishPartialAck() { firstPartial_ = false; }

	void timeout(uint32_t next, uint32_t flight, bool firstForSegment) {
		if (firstForSegment)
			threshold_ = std::max(flight / 2, 2 * mss_);
		window_ = mss_;
		recover_ = next - 1;
		recovering_ = false;
		duplicates_ = limitedBytes_ = credit_ = 0;
	}

	void restartAfterIdle() {
		window_ = std::min(window_, initialWindow_);
		credit_ = 0;
	}

	void windowChanged() { duplicates_ = 0; }

private:
	uint32_t mss_ = 536;
	uint32_t initialWindow_ = 0;
	uint32_t window_ = 0;
	uint32_t threshold_ = std::numeric_limits<uint16_t>::max();
	std::optional<uint32_t> recover_;
	uint32_t duplicates_ = 0;
	uint32_t limitedBytes_ = 0;
	uint32_t credit_ = 0;
	uint32_t inflations_ = 0;
	bool recovering_ = false;
	bool firstPartial_ = false;
};

} // namespace tcp
