#include <atomic>
#include <cassert>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <vector>
#include <unistd.h>

#include <async/recurring-event.hpp>
#include "../../../posix/subsystem/src/pts-read.hpp"
#include "testsuite.hpp"

namespace {

enum class ReadError { eof, wouldBlock, interrupted };

struct ReadEvent {
	template <typename F>
	auto async_wait_if(F condition, async::cancellation_token ct) {
		if (beforeWait)
			beforeWait();
		return event.async_wait_if(std::move(condition), ct);
	}

	void raise() { event.raise(); }

	async::recurring_event event;
	std::function<void()> beforeWait;
};

struct ReadChannel {
	struct Packet {
		std::vector<char> buffer;
		size_t offset = 0;
	};

	std::mutex mutex;
	std::deque<Packet> slaveQueue;
	size_t masterCount = 1;
	std::string devicePath;
	ReadEvent statusBell;
};

struct ReadReceiver {
	void set_value(std::expected<size_t, ReadError> result) {
		assert(!result && result.error() == ReadError::eof);
		*completed = true;
	}

	bool *completed;
};

} // namespace

DEFINE_TEST(pty_blocked_read_hangup, ([] {
	            alarm(5);
	            for (bool closeBeforeWait : {false, true}) {
		            ReadChannel channel;
		            if (closeBeforeWait) {
			            // Close after the loop checks the queue, but before it arms the wait.
			            channel.statusBell.beforeWait = [&] { channel.masterCount = 0; };
		            }
		            std::atomic<bool> nonBlock = false;
		            char byte;
		            bool completed = false;
		            auto operation = async::execution::connect(
		                pts::detail::readSlaveQueue<ReadError>(channel, nonBlock, &byte, 1, {}),
		                ReadReceiver{&completed}
		            );
		            async::execution::start(operation);
		            if (!closeBeforeWait) {
			            // start() runs inline until the actual read loop suspends on the event.
			            assert(!completed);
			            channel.masterCount = 0;
			            channel.statusBell.raise();
		            }
		            assert(completed);
	            }
	            alarm(0);
            }))
