//	stationaryorbit.excryption.test.arcfour:/test.arcfour.cpp
//	Copyright 2021 zawa-ch.
//	GPLv3 (or later) license
//
//	This program is free software: you can redistribute it and/or modify
//	it under the terms of the GNU General Public License as published by
//	the Free Software Foundation, either version 3 of the License, or
//	any later version.
//
//	This program is distributed in the hope that it will be useful,
//	but WITHOUT ANY WARRANTY; without even the implied warranty of
//	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
//	See the GNU General Public License for more details.
//
//	You should have received a copy of the GNU General Public License
//	along with this program.
//	If not, see <http://www.gnu.org/licenses/>.
//
#include <iostream>
#include <array>
#include <functional>
#include "stationaryorbit/encryption.cipher.hpp"
using namespace zawa_ch::StationaryOrbit;
using namespace zawa_ch::StationaryOrbit::Encryption;

constexpr int check_if(bool condition)
{
	if (condition)
	{
		std::cout << "...OK" << std::endl;
		return 0;
	}
	else
	{
		std::cout << "...NG" << std::endl;
		return 1;
	}
}

template<size_t N>
std::ostream& dump(std::ostream& stream, const std::array<std::byte, N>& data)
{
	auto flags = stream.flags();
	auto width = stream.width();
	auto fill = stream.fill();
	size_t n = 0;
	for(auto i: data)
	{
		if(16 <= n)
		{
			n = 0;
			std::cout << std::endl;
		}
		stream.width(2);
		stream.fill('0');
		stream << std::hex << std::uppercase << uint16_t(i);
		++n;
	}
	stream.flags(flags);
	stream.width(width);
	stream.fill(fill);
	return stream;
}
std::ostream& dump(std::ostream& stream, const std::vector<std::byte>& data)
{
	auto flags = stream.flags();
	auto width = stream.width();
	auto fill = stream.fill();
	size_t n = 0;
	for(auto i: data)
	{
		if(16 <= n)
		{
			n = 0;
			std::cout << std::endl;
		}
		stream.width(2);
		stream.fill('0');
		stream << std::hex << std::uppercase << uint16_t(i);
		++n;
	}
	stream.flags(flags);
	stream.width(width);
	stream.fill(fill);
	return stream;
}

// IETF "A Stream Cipher Encryption Algorithm "Arcfour"" 付録のサンプルデータ

const std::array<std::byte, 8> testpattern1_plain = { std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 }, std::byte{ 0x00 } };
const std::vector<std::byte> testpattern1_key = { std::byte{ 0x01 }, std::byte{ 0x23 }, std::byte{ 0x45 }, std::byte{ 0x67 }, std::byte{ 0x89 }, std::byte{ 0xAB }, std::byte{ 0xCD }, std::byte{ 0xEF } };
const std::array<std::byte, 8> testpattern1_cipher = { std::byte{ 0x74 }, std::byte{ 0x94 }, std::byte{ 0xC2 }, std::byte{ 0xE7 }, std::byte{ 0x10 }, std::byte{ 0x4B }, std::byte{ 0x08 }, std::byte{ 0x79 } };
const std::array<std::byte, 5> testpattern2_plain = { std::byte{ 0xdc }, std::byte{ 0xee }, std::byte{ 0x4c }, std::byte{ 0xf9 }, std::byte{ 0x2c } };
const std::vector<std::byte> testpattern2_key = { std::byte{ 0x61 }, std::byte{ 0x8a }, std::byte{ 0x63 }, std::byte{ 0xd2 }, std::byte{ 0xfb } };
const std::array<std::byte, 5> testpattern2_cipher = { std::byte{ 0xf1 }, std::byte{ 0x38 }, std::byte{ 0x29 }, std::byte{ 0xc9 }, std::byte{ 0xde } };
const std::array<std::byte, 309> testpattern3_plain =
{
	std::byte{0x52}, std::byte{0x75}, std::byte{0x69}, std::byte{0x73}, std::byte{0x6c}, std::byte{0x69}, std::byte{0x6e}, std::byte{0x6e},
	std::byte{0x75}, std::byte{0x6e}, std::byte{0x20}, std::byte{0x6c}, std::byte{0x61}, std::byte{0x75}, std::byte{0x6c}, std::byte{0x75},
	std::byte{0x20}, std::byte{0x6b}, std::byte{0x6f}, std::byte{0x72}, std::byte{0x76}, std::byte{0x69}, std::byte{0x73}, std::byte{0x73},
	std::byte{0x73}, std::byte{0x61}, std::byte{0x6e}, std::byte{0x69}, std::byte{0x2c}, std::byte{0x20}, std::byte{0x74}, std::byte{0xe4},
	std::byte{0x68}, std::byte{0x6b}, std::byte{0xe4}, std::byte{0x70}, std::byte{0xe4}, std::byte{0x69}, std::byte{0x64}, std::byte{0x65},
	std::byte{0x6e}, std::byte{0x20}, std::byte{0x70}, std::byte{0xe4}, std::byte{0xe4}, std::byte{0x6c}, std::byte{0x6c}, std::byte{0xe4},
	std::byte{0x20}, std::byte{0x74}, std::byte{0xe4}, std::byte{0x79}, std::byte{0x73}, std::byte{0x69}, std::byte{0x6b}, std::byte{0x75},
	std::byte{0x75}, std::byte{0x2e}, std::byte{0x20}, std::byte{0x4b}, std::byte{0x65}, std::byte{0x73}, std::byte{0xe4}, std::byte{0x79},
	std::byte{0xf6}, std::byte{0x6e}, std::byte{0x20}, std::byte{0x6f}, std::byte{0x6e}, std::byte{0x20}, std::byte{0x6f}, std::byte{0x6e},
	std::byte{0x6e}, std::byte{0x69}, std::byte{0x20}, std::byte{0x6f}, std::byte{0x6d}, std::byte{0x61}, std::byte{0x6e}, std::byte{0x61},
	std::byte{0x6e}, std::byte{0x69}, std::byte{0x2c}, std::byte{0x20}, std::byte{0x6b}, std::byte{0x61}, std::byte{0x73}, std::byte{0x6b},
	std::byte{0x69}, std::byte{0x73}, std::byte{0x61}, std::byte{0x76}, std::byte{0x75}, std::byte{0x75}, std::byte{0x6e}, std::byte{0x20},
	std::byte{0x6c}, std::byte{0x61}, std::byte{0x61}, std::byte{0x6b}, std::byte{0x73}, std::byte{0x6f}, std::byte{0x74}, std::byte{0x20},
	std::byte{0x76}, std::byte{0x65}, std::byte{0x72}, std::byte{0x68}, std::byte{0x6f}, std::byte{0x75}, std::byte{0x75}, std::byte{0x2e},
	std::byte{0x20}, std::byte{0x45}, std::byte{0x6e}, std::byte{0x20}, std::byte{0x6d}, std::byte{0x61}, std::byte{0x20}, std::byte{0x69},
	std::byte{0x6c}, std::byte{0x6f}, std::byte{0x69}, std::byte{0x74}, std::byte{0x73}, std::byte{0x65}, std::byte{0x2c}, std::byte{0x20},
	std::byte{0x73}, std::byte{0x75}, std::byte{0x72}, std::byte{0x65}, std::byte{0x20}, std::byte{0x68}, std::byte{0x75}, std::byte{0x6f},
	std::byte{0x6b}, std::byte{0x61}, std::byte{0x61}, std::byte{0x2c}, std::byte{0x20}, std::byte{0x6d}, std::byte{0x75}, std::byte{0x74},
	std::byte{0x74}, std::byte{0x61}, std::byte{0x20}, std::byte{0x6d}, std::byte{0x65}, std::byte{0x74}, std::byte{0x73}, std::byte{0xe4},
	std::byte{0x6e}, std::byte{0x20}, std::byte{0x74}, std::byte{0x75}, std::byte{0x6d}, std::byte{0x6d}, std::byte{0x75}, std::byte{0x75},
	std::byte{0x73}, std::byte{0x20}, std::byte{0x6d}, std::byte{0x75}, std::byte{0x6c}, std::byte{0x6c}, std::byte{0x65}, std::byte{0x20},
	std::byte{0x74}, std::byte{0x75}, std::byte{0x6f}, std::byte{0x6b}, std::byte{0x61}, std::byte{0x61}, std::byte{0x2e}, std::byte{0x20},
	std::byte{0x50}, std::byte{0x75}, std::byte{0x75}, std::byte{0x6e}, std::byte{0x74}, std::byte{0x6f}, std::byte{0x20}, std::byte{0x70},
	std::byte{0x69}, std::byte{0x6c}, std::byte{0x76}, std::byte{0x65}, std::byte{0x6e}, std::byte{0x2c}, std::byte{0x20}, std::byte{0x6d},
	std::byte{0x69}, std::byte{0x20}, std::byte{0x68}, std::byte{0x75}, std::byte{0x6b}, std::byte{0x6b}, std::byte{0x75}, std::byte{0x75},
	std::byte{0x2c}, std::byte{0x20}, std::byte{0x73}, std::byte{0x69}, std::byte{0x69}, std::byte{0x6e}, std::byte{0x74}, std::byte{0x6f},
	std::byte{0x20}, std::byte{0x76}, std::byte{0x61}, std::byte{0x72}, std::byte{0x61}, std::byte{0x6e}, std::byte{0x20}, std::byte{0x74},
	std::byte{0x75}, std::byte{0x75}, std::byte{0x6c}, std::byte{0x69}, std::byte{0x73}, std::byte{0x65}, std::byte{0x6e}, std::byte{0x2c},
	std::byte{0x20}, std::byte{0x6d}, std::byte{0x69}, std::byte{0x20}, std::byte{0x6e}, std::byte{0x75}, std::byte{0x6b}, std::byte{0x6b},
	std::byte{0x75}, std::byte{0x75}, std::byte{0x2e}, std::byte{0x20}, std::byte{0x54}, std::byte{0x75}, std::byte{0x6f}, std::byte{0x6b},
	std::byte{0x73}, std::byte{0x75}, std::byte{0x74}, std::byte{0x20}, std::byte{0x76}, std::byte{0x61}, std::byte{0x6e}, std::byte{0x61},
	std::byte{0x6d}, std::byte{0x6f}, std::byte{0x6e}, std::byte{0x20}, std::byte{0x6a}, std::byte{0x61}, std::byte{0x20}, std::byte{0x76},
	std::byte{0x61}, std::byte{0x72}, std::byte{0x6a}, std::byte{0x6f}, std::byte{0x74}, std::byte{0x20}, std::byte{0x76}, std::byte{0x65},
	std::byte{0x65}, std::byte{0x6e}, std::byte{0x2c}, std::byte{0x20}, std::byte{0x6e}, std::byte{0x69}, std::byte{0x69}, std::byte{0x73},
	std::byte{0x74}, std::byte{0xe4}, std::byte{0x20}, std::byte{0x73}, std::byte{0x79}, std::byte{0x64}, std::byte{0xe4}, std::byte{0x6d},
	std::byte{0x65}, std::byte{0x6e}, std::byte{0x69}, std::byte{0x20}, std::byte{0x6c}, std::byte{0x61}, std::byte{0x75}, std::byte{0x6c},
	std::byte{0x75}, std::byte{0x6e}, std::byte{0x20}, std::byte{0x74}, std::byte{0x65}, std::byte{0x65}, std::byte{0x6e}, std::byte{0x2e},
	std::byte{0x20}, std::byte{0x2d}, std::byte{0x20}, std::byte{0x45}, std::byte{0x69}, std::byte{0x6e}, std::byte{0x6f}, std::byte{0x20},
	std::byte{0x4c}, std::byte{0x65}, std::byte{0x69}, std::byte{0x6e}, std::byte{0x6f}
};
const std::vector<std::byte> testpattern3_key =
{
	std::byte{0x29}, std::byte{0x04}, std::byte{0x19}, std::byte{0x72}, std::byte{0xfb}, std::byte{0x42}, std::byte{0xba}, std::byte{0x5f},
	std::byte{0xc7}, std::byte{0x12}, std::byte{0x77}, std::byte{0x12}, std::byte{0xf1}, std::byte{0x38}, std::byte{0x29}, std::byte{0xc9}
};
const std::array<std::byte, 309> testpattern3_cipher =
{
	std::byte{0x35}, std::byte{0x81}, std::byte{0x86}, std::byte{0x99}, std::byte{0x90}, std::byte{0x01}, std::byte{0xe6}, std::byte{0xb5},
	std::byte{0xda}, std::byte{0xf0}, std::byte{0x5e}, std::byte{0xce}, std::byte{0xeb}, std::byte{0x7e}, std::byte{0xee}, std::byte{0x21},
	std::byte{0xe0}, std::byte{0x68}, std::byte{0x9c}, std::byte{0x1f}, std::byte{0x00}, std::byte{0xee}, std::byte{0xa8}, std::byte{0x1f},
	std::byte{0x7d}, std::byte{0xd2}, std::byte{0xca}, std::byte{0xae}, std::byte{0xe1}, std::byte{0xd2}, std::byte{0x76}, std::byte{0x3e},
	std::byte{0x68}, std::byte{0xaf}, std::byte{0x0e}, std::byte{0xad}, std::byte{0x33}, std::byte{0xd6}, std::byte{0x6c}, std::byte{0x26},
	std::byte{0x8b}, std::byte{0xc9}, std::byte{0x46}, std::byte{0xc4}, std::byte{0x84}, std::byte{0xfb}, std::byte{0xe9}, std::byte{0x4c},
	std::byte{0x5f}, std::byte{0x5e}, std::byte{0x0b}, std::byte{0x86}, std::byte{0xa5}, std::byte{0x92}, std::byte{0x79}, std::byte{0xe4},
	std::byte{0xf8}, std::byte{0x24}, std::byte{0xe7}, std::byte{0xa6}, std::byte{0x40}, std::byte{0xbd}, std::byte{0x22}, std::byte{0x32},
	std::byte{0x10}, std::byte{0xb0}, std::byte{0xa6}, std::byte{0x11}, std::byte{0x60}, std::byte{0xb7}, std::byte{0xbc}, std::byte{0xe9},
	std::byte{0x86}, std::byte{0xea}, std::byte{0x65}, std::byte{0x68}, std::byte{0x80}, std::byte{0x03}, std::byte{0x59}, std::byte{0x6b},
	std::byte{0x63}, std::byte{0x0a}, std::byte{0x6b}, std::byte{0x90}, std::byte{0xf8}, std::byte{0xe0}, std::byte{0xca}, std::byte{0xf6},
	std::byte{0x91}, std::byte{0x2a}, std::byte{0x98}, std::byte{0xeb}, std::byte{0x87}, std::byte{0x21}, std::byte{0x76}, std::byte{0xe8},
	std::byte{0x3c}, std::byte{0x20}, std::byte{0x2c}, std::byte{0xaa}, std::byte{0x64}, std::byte{0x16}, std::byte{0x6d}, std::byte{0x2c},
	std::byte{0xce}, std::byte{0x57}, std::byte{0xff}, std::byte{0x1b}, std::byte{0xca}, std::byte{0x57}, std::byte{0xb2}, std::byte{0x13},
	std::byte{0xf0}, std::byte{0xed}, std::byte{0x1a}, std::byte{0xa7}, std::byte{0x2f}, std::byte{0xb8}, std::byte{0xea}, std::byte{0x52},
	std::byte{0xb0}, std::byte{0xbe}, std::byte{0x01}, std::byte{0xcd}, std::byte{0x1e}, std::byte{0x41}, std::byte{0x28}, std::byte{0x67},
	std::byte{0x72}, std::byte{0x0b}, std::byte{0x32}, std::byte{0x6e}, std::byte{0xb3}, std::byte{0x89}, std::byte{0xd0}, std::byte{0x11},
	std::byte{0xbd}, std::byte{0x70}, std::byte{0xd8}, std::byte{0xaf}, std::byte{0x03}, std::byte{0x5f}, std::byte{0xb0}, std::byte{0xd8},
	std::byte{0x58}, std::byte{0x9d}, std::byte{0xbc}, std::byte{0xe3}, std::byte{0xc6}, std::byte{0x66}, std::byte{0xf5}, std::byte{0xea},
	std::byte{0x8d}, std::byte{0x4c}, std::byte{0x79}, std::byte{0x54}, std::byte{0xc5}, std::byte{0x0c}, std::byte{0x3f}, std::byte{0x34},
	std::byte{0x0b}, std::byte{0x04}, std::byte{0x67}, std::byte{0xf8}, std::byte{0x1b}, std::byte{0x42}, std::byte{0x59}, std::byte{0x61},
	std::byte{0xc1}, std::byte{0x18}, std::byte{0x43}, std::byte{0x07}, std::byte{0x4d}, std::byte{0xf6}, std::byte{0x20}, std::byte{0xf2},
	std::byte{0x08}, std::byte{0x40}, std::byte{0x4b}, std::byte{0x39}, std::byte{0x4c}, std::byte{0xf9}, std::byte{0xd3}, std::byte{0x7f},
	std::byte{0xf5}, std::byte{0x4b}, std::byte{0x5f}, std::byte{0x1a}, std::byte{0xd8}, std::byte{0xf6}, std::byte{0xea}, std::byte{0x7d},
	std::byte{0xa3}, std::byte{0xc5}, std::byte{0x61}, std::byte{0xdf}, std::byte{0xa7}, std::byte{0x28}, std::byte{0x1f}, std::byte{0x96},
	std::byte{0x44}, std::byte{0x63}, std::byte{0xd2}, std::byte{0xcc}, std::byte{0x35}, std::byte{0xa4}, std::byte{0xd1}, std::byte{0xb0},
	std::byte{0x34}, std::byte{0x90}, std::byte{0xde}, std::byte{0xc5}, std::byte{0x1b}, std::byte{0x07}, std::byte{0x11}, std::byte{0xfb},
	std::byte{0xd6}, std::byte{0xf5}, std::byte{0x5f}, std::byte{0x79}, std::byte{0x23}, std::byte{0x4d}, std::byte{0x5b}, std::byte{0x7c},
	std::byte{0x76}, std::byte{0x66}, std::byte{0x22}, std::byte{0xa6}, std::byte{0x6d}, std::byte{0xe9}, std::byte{0x2b}, std::byte{0xe9},
	std::byte{0x96}, std::byte{0x46}, std::byte{0x1d}, std::byte{0x5e}, std::byte{0x4d}, std::byte{0xc8}, std::byte{0x78}, std::byte{0xef},
	std::byte{0x9b}, std::byte{0xca}, std::byte{0x03}, std::byte{0x05}, std::byte{0x21}, std::byte{0xe8}, std::byte{0x35}, std::byte{0x1e},
	std::byte{0x4b}, std::byte{0xae}, std::byte{0xd2}, std::byte{0xfd}, std::byte{0x04}, std::byte{0xf9}, std::byte{0x46}, std::byte{0x73},
	std::byte{0x68}, std::byte{0xc4}, std::byte{0xad}, std::byte{0x6a}, std::byte{0xc1}, std::byte{0x86}, std::byte{0xd0}, std::byte{0x82},
	std::byte{0x45}, std::byte{0xb2}, std::byte{0x63}, std::byte{0xa2}, std::byte{0x66}, std::byte{0x6d}, std::byte{0x1f}, std::byte{0x6c},
	std::byte{0x54}, std::byte{0x20}, std::byte{0xf1}, std::byte{0x59}, std::byte{0x9d}, std::byte{0xfd}, std::byte{0x9f}, std::byte{0x43},
	std::byte{0x89}, std::byte{0x21}, std::byte{0xc2}, std::byte{0xf5}, std::byte{0xa4}, std::byte{0x63}, std::byte{0x93}, std::byte{0x8c},
	std::byte{0xe0}, std::byte{0x98}, std::byte{0x22}, std::byte{0x65}, std::byte{0xee}, std::byte{0xf7}, std::byte{0x01}, std::byte{0x79},
	std::byte{0xbc}, std::byte{0x55}, std::byte{0x3f}, std::byte{0x33}, std::byte{0x9e}, std::byte{0xb1}, std::byte{0xa4}, std::byte{0xc1},
	std::byte{0xaf}, std::byte{0x5f}, std::byte{0x6a}, std::byte{0x54}, std::byte{0x7f}
};

std::array<std::function<int(void)>, 7> tests =
{
	[]()
	{
		std::cout << "1. Type ArcFourGenerator meets the traits Iterator?";
		return check_if(IteratorTraits::IsIterator<ArcFourGenerator>);
	},
	[]()
	{
		std::cout << "plain text: ";
		dump(std::cout, testpattern1_plain) << std::endl;
		std::cout << "encryption key: ";
		dump(std::cout, testpattern1_key) << std::endl;
		auto enc = ArcFourEncrypter(ArcFourGenerator(testpattern1_key));
		auto enc_result = decltype(testpattern1_plain)();
		auto ii = testpattern1_plain.cbegin();
		auto oi = enc_result.begin();
		auto ie = testpattern1_plain.cend();
		auto oe = enc_result.end();
		while((ii != ie) && (oi != oe))
		{
			*oi = enc.encrypt(*ii);
			++ii;
			++oi;
		}
		std::cout << "2. encrypted text ? ";
		dump(std::cout, enc_result) << std::endl;
		return 0;
	},
	[]()
	{
		std::cout << "encrypted text: ";
		dump(std::cout, testpattern1_cipher) << std::endl;
		std::cout << "encryption key: ";
		dump(std::cout, testpattern1_key) << std::endl;
		auto enc = ArcFourDecrypter(ArcFourGenerator(testpattern1_key));
		auto enc_result = decltype(testpattern1_cipher)();
		auto ii = testpattern1_cipher.cbegin();
		auto oi = enc_result.begin();
		auto ie = testpattern1_cipher.cend();
		auto oe = enc_result.end();
		while((ii != ie) && (oi != oe))
		{
			*oi = enc.decrypt(*ii);
			++ii;
			++oi;
		}
		std::cout << "3. plain text ? ";
		dump(std::cout, enc_result) << std::endl;
		return 0;
	},
	[]()
	{
		std::cout << "plain text: ";
		dump(std::cout, testpattern2_plain) << std::endl;
		std::cout << "encryption key: ";
		dump(std::cout, testpattern2_key) << std::endl;
		auto enc = ArcFourEncrypter(ArcFourGenerator(testpattern2_key));
		auto enc_result = decltype(testpattern2_plain)();
		auto ii = testpattern2_plain.cbegin();
		auto oi = enc_result.begin();
		auto ie = testpattern2_plain.cend();
		auto oe = enc_result.end();
		while((ii != ie) && (oi != oe))
		{
			*oi = enc.encrypt(*ii);
			++ii;
			++oi;
		}
		std::cout << "4. encrypted text ? ";
		dump(std::cout, enc_result) << std::endl;
		return 0;
	},
	[]()
	{
		std::cout << "encrypted text: ";
		dump(std::cout, testpattern2_cipher) << std::endl;
		std::cout << "encryption key: ";
		dump(std::cout, testpattern2_key) << std::endl;
		auto enc = ArcFourDecrypter(ArcFourGenerator(testpattern2_key));
		auto enc_result = decltype(testpattern2_cipher)();
		auto ii = testpattern2_cipher.cbegin();
		auto oi = enc_result.begin();
		auto ie = testpattern2_cipher.cend();
		auto oe = enc_result.end();
		while((ii != ie) && (oi != oe))
		{
			*oi = enc.decrypt(*ii);
			++ii;
			++oi;
		}
		std::cout << "5. plain text ? ";
		dump(std::cout, enc_result) << std::endl;
		return 0;
	},
	[]()
	{
		std::cout << "plain text: ";
		dump(std::cout, testpattern3_plain) << std::endl;
		std::cout << "encryption key: ";
		dump(std::cout, testpattern3_key) << std::endl;
		auto enc = ArcFourEncrypter(ArcFourGenerator(testpattern3_key));
		auto enc_result = decltype(testpattern3_plain)();
		auto ii = testpattern3_plain.cbegin();
		auto oi = enc_result.begin();
		auto ie = testpattern3_plain.cend();
		auto oe = enc_result.end();
		while((ii != ie) && (oi != oe))
		{
			*oi = enc.encrypt(*ii);
			++ii;
			++oi;
		}
		std::cout << "6. encrypted text ? ";
		dump(std::cout, enc_result) << std::endl;
		return 0;
	},
	[]()
	{
		std::cout << "encrypted text: ";
		dump(std::cout, testpattern3_cipher) << std::endl;
		std::cout << "encryption key: ";
		dump(std::cout, testpattern3_key) << std::endl;
		auto enc = ArcFourDecrypter(ArcFourGenerator(testpattern3_key));
		auto enc_result = decltype(testpattern3_cipher)();
		auto ii = testpattern3_cipher.cbegin();
		auto oi = enc_result.begin();
		auto ie = testpattern3_cipher.cend();
		auto oe = enc_result.end();
		while((ii != ie) && (oi != oe))
		{
			*oi = enc.decrypt(*ii);
			++ii;
			++oi;
		}
		std::cout << "7. plain text ? ";
		dump(std::cout, enc_result) << std::endl;
		return 0;
	},
};


int main(int argc, char const *argv[])
{
	std::cout << "<--- ArcFour --->" << std::endl;
	if (argc < 2)
	{
		std::cerr << "E: At least 1 argument is required";
		return 2;
	}

	auto test_index = std::stoi(argv[1]);
	if (0 < test_index && test_index <= tests.size() )
	{
		return tests[test_index - 1]();
	}
	else
	{
		std::cerr << "Invalid test index";
		return 2;
	}
}
