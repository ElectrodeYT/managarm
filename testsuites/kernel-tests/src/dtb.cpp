#include "testsuite.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <vector>

#include "../../../kernel/common/dtb.hpp"

namespace {

std::vector<std::byte> makeDtb(unsigned mode) {
	std::vector<std::byte> data(56);
	auto word = [&](uint32_t value) {
		for (int shift = 24; shift >= 0; shift -= 8)
			data.push_back(static_cast<std::byte>(value >> shift));
	};
	auto property = [&](uint32_t name, uint32_t value) {
		word(3);
		word(4);
		word(name);
		word(value);
	};
	word(1);
	word(0); // Root BEGIN_NODE and padded empty name.
	if (mode & 2) {
		word(4);
		word(4);
	}
	if (mode & 1) {
		property(0, 42);
		if (mode & 4)
			word(4);
		property(6, 43);
	}
	if (mode & 8)
		word(4);
	if (mode & 16) {
		word(1);
		for (char c : std::string_view{"child"})
			data.push_back(static_cast<std::byte>(c));
		data.push_back(std::byte{0});
		while (data.size() % 4)
			data.push_back(std::byte{0});
		property(6, 99); // Must not leak into the root's property iterator.
		word(2);
	}
	word(2);
	word(9);
	auto strings = data.size();
	for (char c : "first\0second")
		data.push_back(static_cast<std::byte>(c));
	auto put = [&](size_t offset, uint32_t value) {
		for (size_t i = 0; i < 4; ++i)
			data[offset + i] = static_cast<std::byte>(value >> (24 - i * 8));
	};
	put(0, 0xd00dfeed);
	put(4, data.size());
	put(8, 56);
	put(12, strings);
	put(16, 40);
	put(20, 17);
	put(24, 16);
	put(32, 13);
	put(36, strings - 56);
	return data;
}

} // namespace

DEFINE_TEST(dtb_property_padding, ([] {
	            for (unsigned mode = 0; mode < 32; ++mode) {
		            auto data = makeDtb(mode);
		            DeviceTree tree{data.data()};
		            auto root = tree.rootNode();
		            size_t count = 0;
		            for (auto prop : root.properties()) {
			            assert(count < 2);
			            assert(std::string_view{prop.name()} == (count ? "second" : "first"));
			            assert(prop.asU32() == (count ? 43 : 42));
			            ++count;
		            }
		            assert(count == ((mode & 1) ? 2 : 0));
		            assert(
		                static_cast<bool>(root.findProperty("second"))
		                == static_cast<bool>(mode & 1)
		            );
	            }
	            DeviceTreeNode empty;
	            assert(empty.properties().begin() == empty.properties().end());
            }))
