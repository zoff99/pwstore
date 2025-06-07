#! /bin/bash


_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_


echo $_HOME_
cd $_HOME_

            add_config_flag() { CONFIG_FLAGS="$CONFIG_FLAGS $@";    }
            add_c_flag()      { C_FLAGS="$C_FLAGS $@";              }
            add_cxx_flag()    { CXX_FLAGS="$CXX_FLAGS $@";          }
            add_ld_flag()     { LD_FLAGS="$LD_FLAGS $@";            }
            add_flag()        { add_c_flag "$@"; add_cxx_flag "$@"; }
            unset CONFIG_FLAGS
            unset C_FLAGS
            unset CXX_FLAGS
            unset LD_FLAGS
            unset CFLAGS
            unset CXXFLAGS
            unset CPPFLAGS
            unset LDFLAGS

            add_flag -O2 -march=native
            add_c_flag -pedantic
            # add_c_flag -std=c99
            add_flag -g3
            add_flag -ftrapv
            # -- Add all warning flags we can --
            add_flag -Wall
            add_flag -Wextra
            add_flag -Weverything
            add_flag -Werror
            add_flag -fdiagnostics-color=always
            add_flag -fno-omit-frame-pointer
            add_flag -fsanitize=address
            add_flag -fstack-protector-all
            add_flag --param=ssp-buffer-size=1
            add_flag -D_FORTIFY_SOURCE=2
            add_flag -Wno-unknown-pragmas

            clang-14 $C_FLAGS -g -D LINUX ../pwstore.c -o ../pwstore

