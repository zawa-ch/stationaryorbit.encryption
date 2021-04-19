//	stationaryorbit.encryption:/arcfour
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
#include "stationaryorbit/encryption/arcfour.hpp"

static_assert(zawa_ch::StationaryOrbit::IteratorTraits::IsIterator<zawa_ch::StationaryOrbit::Encryption::ArcFourGenerator>, "zawa_ch::StationaryOrbit::Encryption::ArcFourGenerator は zawa_ch::StationaryOrbit::IteratorTraits::IsIterator の要件を満たしませんでした。");
