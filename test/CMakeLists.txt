# stationaryorbit.encryption:/test/CMakeLists.txt
# Copyright 2021 zawa-ch.
# GPLv3 (or later) license
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.
# If not, see <http://www.gnu.org/licenses/>.
#

include(CTest)
function(do_test_nofail target index)
    add_test(NAME ${target}.${index} COMMAND ${target} ${index})
    set_tests_properties(${target}.${index}
    PROPERTIES
        PASS_REGULAR_EXPRESSION "\.\.\.OK"
        FAIL_REGULAR_EXPRESSION "NG"
        SKIP_RETURN_CODE 255
)
endfunction(do_test_nofail)
function(do_test_pattern target index pattern)
    add_test(NAME ${target}.${index} COMMAND ${target} ${index})
    set_tests_properties(${target}.${index}
    PROPERTIES
        PASS_REGULAR_EXPRESSION ${pattern}
        SKIP_RETURN_CODE 255
)
endfunction(do_test_pattern)

add_executable(stationaryorbit.encryption.test.arcfour test.arcfour.cpp)
target_link_libraries(stationaryorbit.encryption.test.arcfour
    stationaryorbit.encryption
)
do_test_nofail(stationaryorbit.encryption.test.arcfour 1)
do_test_pattern(stationaryorbit.encryption.test.arcfour 2 "encrypted text . 7494C2E7104B0879")
do_test_pattern(stationaryorbit.encryption.test.arcfour 3 "plain text . 0000000000000000")
do_test_pattern(stationaryorbit.encryption.test.arcfour 4 "encrypted text . F13829C9DE")
do_test_pattern(stationaryorbit.encryption.test.arcfour 5 "plain text . DCEE4CF92C")
do_test_pattern(stationaryorbit.encryption.test.arcfour 6 "encrypted text . 358186999001E6B5DAF05ECEEB7EEE21
E0689C1F00EEA81F7DD2CAAEE1D2763E
68AF0EAD33D66C268BC946C484FBE94C
5F5E0B86A59279E4F824E7A640BD2232
10B0A61160B7BCE986EA65688003596B
630A6B90F8E0CAF6912A98EB872176E8
3C202CAA64166D2CCE57FF1BCA57B213
F0ED1AA72FB8EA52B0BE01CD1E412867
720B326EB389D011BD70D8AF035FB0D8
589DBCE3C666F5EA8D4C7954C50C3F34
0B0467F81B425961C11843074DF620F2
08404B394CF9D37FF54B5F1AD8F6EA7D
A3C561DFA7281F964463D2CC35A4D1B0
3490DEC51B0711FBD6F55F79234D5B7C
766622A66DE92BE996461D5E4DC878EF
9BCA030521E8351E4BAED2FD04F94673
68C4AD6AC186D08245B263A2666D1F6C
5420F1599DFD9F438921C2F5A463938C
E0982265EEF70179BC553F339EB1A4C1
AF5F6A547F")
do_test_pattern(stationaryorbit.encryption.test.arcfour 7 "plain text . 527569736C696E6E756E206C61756C75
206B6F727669737373616E692C2074E4
686BE470E46964656E2070E4E46C6CE4
2074E47973696B75752E204B6573E479
F66E206F6E206F6E6E69206F6D616E61
6E692C206B61736B6973617675756E20
6C61616B736F7420766572686F75752E
20456E206D6120696C6F697473652C20
737572652068756F6B61612C206D7574
7461206D657473E46E2074756D6D7575
73206D756C6C652074756F6B61612E20
5075756E746F2070696C76656E2C206D
692068756B6B75752C207369696E746F
20766172616E207475756C6973656E2C
206D69206E756B6B75752E2054756F6B
7375742076616E616D6F6E206A612076
61726A6F74207665656E2C206E696973
74E420737964E46D656E69206C61756C
756E207465656E2E202D2045696E6F20
4C65696E6F")
