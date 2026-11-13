#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>

namespace ata {

inline constexpr std::size_t sectorBytes = 512;
inline constexpr std::uint8_t masterLbaDevice = 0xe0;

constexpr bool contains(std::uint64_t sector, std::size_t count, std::uint64_t limit) {
	return count && sector < limit && count <= limit - sector;
}

constexpr bool validRequest(std::uint64_t sector, std::size_t bytes, bool lba48) {
	auto count = bytes / sectorBytes;
	auto limit = std::uint64_t{1} << (lba48 ? 48 : 28);
	return !(bytes % sectorBytes) && count <= 255 && contains(sector, count, limit);
}

constexpr std::uint8_t deviceRegister(std::uint64_t sector, bool lba48) {
	return masterLbaDevice | (lba48 ? 0 : static_cast<std::uint8_t>((sector >> 24) & 0xf));
}

struct Identification {
	std::uint64_t sectors;
	bool lba48;
};

inline std::optional<Identification> identify(std::span<const std::uint8_t, 512> data) {
	auto word = [&](std::size_t index) -> std::uint16_t {
		return data[2 * index] | (std::uint16_t{data[2 * index + 1]} << 8);
	};
	if (!(word(49) & (1 << 9)))
		return std::nullopt; // CHS devices are not supported.
	if ((word(106) & 0xd000) == 0x5000) {
		auto logicalWords = word(117) | (std::uint32_t{word(118)} << 16);
		if (logicalWords != sectorBytes / 2)
			return std::nullopt;
	}
	bool lba48 = (word(83) & 0xc000) == 0x4000 && (word(83) & (1 << 10));
	std::uint64_t sectors = word(60) | (std::uint64_t{word(61)} << 16);
	if (lba48)
		sectors = word(100) | (std::uint64_t{word(101)} << 16) | (std::uint64_t{word(102)} << 32)
		          | (std::uint64_t{word(103)} << 48);
	auto limit = std::uint64_t{1} << (lba48 ? 48 : 28);
	if (!sectors || sectors > limit
	    || sectors > std::numeric_limits<std::size_t>::max() / sectorBytes)
		return std::nullopt;
	return Identification{sectors, lba48};
}

} // namespace ata
