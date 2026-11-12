#pragma once

#include <cstddef>
#include <async/result.hpp>
#include <frg/expected.hpp>

namespace posix::detail {

template <typename Error, typename File, typename MapError>
async::result<frg::expected<Error, size_t>>
writeDeviceAll(File &file, const void *data, size_t length, MapError mapError) {
	size_t progress = 0;
	while (progress < length) {
		auto chunk = co_await file.writeSome(
		    reinterpret_cast<const char *>(data) + progress, length - progress
		);
		if (!chunk || !*chunk) {
			if (progress)
				co_return progress;
			co_return chunk ? Error::ioError : mapError(chunk.error());
		}
		progress += *chunk;
	}
	co_return length;
}

} // namespace posix::detail
