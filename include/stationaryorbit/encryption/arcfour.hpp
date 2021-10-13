//	stationaryorbit/encryption/arcfour
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
#ifndef __stationaryorbit_encryption_arcfour__
#define __stationaryorbit_encryption_arcfour__
#include <stdexcept>
#include <array>
#include <vector>
#include <stationaryorbit/core.numeral.hpp>
namespace zawa_ch::StationaryOrbit::Encryption
{
	class ArcFourGenerator
	{
	public:
		typedef std::byte ValueType;
	private:
		std::array<std::byte, 256> s;
		size_t i;
		size_t j;
		std::byte c;
	public:
		ArcFourGenerator(const std::vector<std::byte>& key) : s(initialize_sbox(key)), i(0), j(0), c()
		{
			Next();
		}
		template<size_t N>
		constexpr ArcFourGenerator(const std::array<std::byte, N>& key) : s(initialize_sbox(key)), i(0), j(0), c()
		{
			Next();
		}

		[[nodiscard]] constexpr bool HasValue() const noexcept { return std::true_type::value; }
		[[nodiscard]] constexpr const ValueType& Current() const noexcept { return c; }
		constexpr bool Next() noexcept
		{
			i = (i + 1) % 256;
			j = (j + size_t(s[i])) % 256;
			auto t = s[j];
			s[j] = s[i];
			s[i] = t;
			c = s[(size_t(s[i]) + size_t(s[j])) % 256];
			return std::true_type::value;
		}
		[[nodiscard]] bool Equals(const ArcFourGenerator& other) const noexcept
		{
			return (s == other.s) && (i == other.i) && (j == other.j) && (c == other.c);
		}
		[[nodiscard]] bool operator==(const ArcFourGenerator& other) const noexcept { return Equals(other); }
		[[nodiscard]] bool operator!=(const ArcFourGenerator& other) const noexcept { return !Equals(other); }
	private:
		[[nodiscard]] static constexpr std::array<std::byte, 256> construct_sbox()
		{
			auto result = std::array<std::byte, 256>();
			uint8_t n = 0;
			for(auto& i: result)
			{
				i = std::byte{ n };
				++n;
			}
			return result;
		}
		[[nodiscard]] static std::array<std::byte, 256> construct_key(const std::vector<std::byte>& key)
		{
			auto result = std::array<std::byte, 256>();
			size_t n = 0;
			size_t l = key.size();
			for(auto& i: result)
			{
				i = key[n % l];
				++n;
			}
			return result;
		}
		template<size_t N>
		[[nodiscard]] static constexpr std::array<std::byte, 256> construct_key(const std::array<std::byte, N>& key)
		{
			auto result = std::array<std::byte, 256>();
			size_t n = 0;
			size_t l = key.size();
			for(auto& i: result)
			{
				i = key[n % l];
				++n;
			}
			return result;
		}
		[[nodiscard]] static std::array<std::byte, 256> initialize_sbox(const std::vector<std::byte>& key)
		{
			if ((key.size() * 8) < 40) { throw std::invalid_argument("invalid key length"); }
			auto result = construct_sbox();
			auto skey = construct_key(key);
			size_t j = 0;
			auto r = Range<size_t>(0, 256);
			for(auto i: r.get_std_iterator())
			{
				j = (j + size_t(result[i]) + size_t(skey[i])) % 256;
				auto t = result[j];
				result[j] = result[i];
				result[i] = t;
			}
			return result;
		}
		template<size_t N>
		[[nodiscard]] static constexpr std::array<std::byte, 256> initialize_sbox(const std::array<std::byte, N>& key)
		{
			static_assert((N * 8) < 40, "invalid key length");
			auto result = construct_sbox();
			auto skey = construct_key(key);
			size_t j = 0;
			auto r = Range<size_t>(0, 256);
			for(auto i: r.get_std_iterator())
			{
				j = (j + size_t(result[i]) + size_t(skey[i])) % 256;
				auto t = result[j];
				result[j] = result[i];
				result[i] = t;
			}
			return result;
		}
	};
	class ArcFourEncrypter
	{
	public:
		typedef std::byte DataType;
	private:
		ArcFourGenerator generator;
	public:
		constexpr ArcFourEncrypter(const ArcFourGenerator& generator) : generator(generator) {}

		[[nodiscard]] constexpr const ArcFourGenerator& get_generator() const noexcept { return generator; }
		[[nodiscard]] constexpr DataType encrypt(const DataType& data)
		{
			auto result = data ^ generator.Current();
			generator.Next();
			return result;
		}
	};
	class ArcFourDecrypter
	{
	public:
		typedef std::byte DataType;
	private:
		ArcFourGenerator generator;
	public:
		constexpr ArcFourDecrypter(const ArcFourGenerator& generator) : generator(generator) {}

		[[nodiscard]] constexpr const ArcFourGenerator& get_generator() const noexcept { return generator; }
		[[nodiscard]] constexpr DataType decrypt(const DataType& data)
		{
			auto result = data ^ generator.Current();
			generator.Next();
			return result;
		}
	};
}
#endif // __stationaryorbit_encryption_arcfour__
