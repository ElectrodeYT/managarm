#include <cassert>
#include <cstring>
#include <expected>

#include <async/algorithm.hpp>
#include "../../../posix/subsystem/src/device-write.hpp"
#include "testsuite.hpp"

namespace {

enum class WriteError { ioError, brokenPipe };

struct ShortWriter {
	async::result<std::expected<size_t, WriteError>> writeSome(const void *data, size_t length) {
		++calls;
		if (calls == 1) {
			assert(length == 7 && !memcmp(data, "payload", 7));
			co_return 3;
		}
		assert(calls == 2);
		assert(length == 4 && !memcmp(data, "load", 4));
		if (zeroProgress)
			co_return 0;
		co_return std::unexpected{WriteError::brokenPipe};
	}

	bool zeroProgress;
	int calls = 0;
};

} // namespace

DEFINE_TEST(device_write_preserves_partial_progress, ([] {
	            for (bool zeroProgress : {false, true}) {
		            ShortWriter writer{zeroProgress};
		            auto result = async::run(posix::detail::writeDeviceAll<WriteError>(
		                writer, "payload", 7, [](WriteError error) { return error; }
		            ));
		            assert(result && result.value() == 3);
		            assert(writer.calls == 2);
	            }
            }))
