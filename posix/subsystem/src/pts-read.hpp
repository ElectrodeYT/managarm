#pragma once

#include <algorithm>
#include <atomic>
#include <cstring>
#include <expected>
#include <iostream>
#include <mutex>
#include <async/recurring-event.hpp>
#include <async/result.hpp>

namespace pts::detail {

template <typename Error, typename Channel>
async::result<std::expected<size_t, Error>> readSlaveQueue(
    Channel &channel, const std::atomic<bool> &nonBlock, void *data, size_t maxLength,
    async::cancellation_token ce, bool logReadWrite = false
) {
	if(!maxLength)
		co_return std::unexpected{Error::eof};

	{
		std::lock_guard lock{channel.mutex};
		if(channel.masterCount == 0)
			co_return std::unexpected{Error::eof};
	}

	while(true) {
		{
			std::lock_guard lock{channel.mutex};
			if(!channel.slaveQueue.empty()) {
				auto packet = &channel.slaveQueue.front();
				auto chunk = std::min(packet->buffer.size() - packet->offset, maxLength);
				if(chunk)
					memcpy(data, packet->buffer.data() + packet->offset, chunk);
				packet->offset += chunk;
				if(packet->offset == packet->buffer.size())
					channel.slaveQueue.pop_front();
				co_return chunk;
			}

			if (!channel.masterCount)
				co_return std::unexpected{Error::eof};

			if(nonBlock){
				if(logReadWrite)
					std::cout << "posix: tty would block" << std::endl;
				co_return std::unexpected{Error::wouldBlock};
			}
		}

		auto waitResult = co_await channel.statusBell.async_wait_if([&] {
			std::lock_guard lock{channel.mutex};
			return channel.slaveQueue.empty() && channel.masterCount;
		}, ce);
		if (!waitResult) {
			if (logReadWrite)
				std::cout << "posix: tty read interrupted" << std::endl;
			co_return std::unexpected{Error::interrupted};
		}
	}
}

} // namespace pts::detail
