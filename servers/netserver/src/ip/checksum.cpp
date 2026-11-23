#include "checksum.hpp"

#include <arch/bit.hpp>

void Checksum::update(uint16_t word)  {
	state_ += word;
	while (state_ >> 16 != 0) {
		state_ = (state_ >> 16) + (state_ & 0xffff);
	}
}

void Checksum::update(const void *data, size_t size) {
	auto iter = static_cast<const unsigned char*>(data);
	auto end = iter + (size & ~size_t{1});
	for (; iter < end; iter += 2) {
		update(iter[0] << 8 | iter[1]);
	}
	if (size & 1)
		update(iter[0] << 8);
}

void Checksum::update(arch::dma_buffer_view view) {
	update(view.data(), view.size());
}

uint16_t Checksum::finalize() {
	auto state_ = this->state_;
	return ~state_;
}
