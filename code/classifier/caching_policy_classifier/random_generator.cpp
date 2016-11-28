#include "random_generator.h"
#include <algorithm>
#include <random>
#include <ctime>

std::default_random_engine e((unsigned int)std::time(0));

std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
//			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[e() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}

uint16_t random_uint16() {
	return (uint16_t)(e() & 0xffff);
}
