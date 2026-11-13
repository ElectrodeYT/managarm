#pragma once

#include <cstddef>
#include <cstdint>

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

} // namespace ata
