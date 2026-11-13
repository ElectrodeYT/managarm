#include "testsuite.hpp"

#include "../../../drivers/block/ata/src/command.hpp"

#include <array>
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
	            std::array<std::uint8_t, 512> id{};
	            auto put = [&](std::size_t index, std::uint16_t value) {
		            id[2 * index] = value & 0xff;
		            id[2 * index + 1] = value >> 8;
	            };
	            assert(!ata::identify(id));
	            put(49, 1 << 9);
	            assert(!ata::identify(id));
	            put(60, 0x1234);
	            put(61, 0x12);
	            auto geometry = ata::identify(id);
	            assert(geometry && geometry->sectors == 0x121234 && !geometry->lba48);
	            put(83, 1 << 10); // Invalid command-set word: keep the legacy capacity.
	            put(100, 7);
	            geometry = ata::identify(id);
	            assert(geometry && geometry->sectors == 0x121234 && !geometry->lba48);
	            put(83, 0x4000 | (1 << 10));
	            put(101, 0x1234);
	            put(102, 0x12);
	            geometry = ata::identify(id);
	            assert(geometry && geometry->sectors == 0x1212340007 && geometry->lba48);
	            // 48-bit support is reported by word 83, not the enabled-feature word 86.
	            put(86, 0);
	            assert(ata::identify(id)->lba48);
	            put(103, 2); // Beyond the command address space.
	            assert(!ata::identify(id));
	            put(103, 0);
	            put(106, 0x5000);
	            put(117, 2048); // Unsupported 4 KiB logical sector.
	            assert(!ata::identify(id));
	            put(117, 256);
	            assert(ata::identify(id));
	            put(100, 0);
	            put(101, 0);
	            put(102, 0);
	            assert(!ata::identify(id));
	            put(83, 0);
	            put(60, 0xffff);
	            put(61, 0xffff);
	            assert(!ata::identify(id));
            }))
