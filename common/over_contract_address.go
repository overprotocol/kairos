// Copyright 2024 The kairos Authors
// This file is part of the kairos library.
//
// The kairos library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The kairos library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the kairos library. If not, see <http://www.gnu.org/licenses/>.

package common

var (
	overPrecompiledContractsAddressOffset = byte(0xf5)
)

func overPrecompileAddress(index byte) Address {
	return BytesToAddress([]byte{overPrecompiledContractsAddressOffset - index})
}

var (
	CreateWithUiHashAddress  = overPrecompileAddress(0) // f5
	Create2WithUiHashAddress = overPrecompileAddress(1) // f4
	ChangeUiHashAddress      = overPrecompileAddress(2) // f3
)

func IsCreationPrecompiled(address Address) bool {
	return address == CreateWithUiHashAddress || address == Create2WithUiHashAddress
}
