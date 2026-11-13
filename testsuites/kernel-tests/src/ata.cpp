#include "testsuite.hpp"

#include "../../../drivers/block/ata/src/command.hpp"

#include <cassert>
#include <limits>

DEFINE_TEST(ata_command_bounds, ([] {
	            constexpr auto lba28 = std::uint64_t{1} << 28;
	            constexpr auto lba48 = std::uint64_t{1} << 48;
	            static_assert(ata::deviceRegister(0, false) == 0xe0);
	            static_assert(ata::deviceRegister(0x0a123456, false) == 0xea);
	            static_assert(ata::deviceRegister(0x0fffffff, false) == 0xef);
	            static_assert(ata::deviceRegister(0x123456789abc, true) == 0xe0);
	            static_assert(ata::validRequest(0, 512, false));
	            static_assert(ata::validRequest(lba28 - 1, 512, false));
	            static_assert(!ata::validRequest(lba28 - 1, 1024, false));
	            static_assert(!ata::validRequest(lba28, 512, false));
	            static_assert(ata::validRequest(lba48 - 1, 512, true));
	            static_assert(!ata::validRequest(lba48 - 1, 1024, true));
	            static_assert(!ata::validRequest(lba48, 512, true));
	            static_assert(
	                !ata::validRequest(std::numeric_limits<std::uint64_t>::max(), 512, true)
	            );
	            static_assert(!ata::validRequest(0, 0, false));
	            static_assert(!ata::validRequest(0, 511, false));
	            static_assert(!ata::validRequest(0, 513, false));
	            static_assert(ata::validRequest(0, 255 * 512, false));
	            static_assert(!ata::validRequest(0, 256 * 512, false));
	            static_assert(ata::contains(99, 1, 100));
	            static_assert(!ata::contains(99, 2, 100));
            }))
