#! /bin/sh

exec clang -g -Weverything -Wno-unused -Wno-unused-parameter -Wno-incompatible-pointer-types-discards-qualifiers -dynamiclib -o 42.dylib c_hook.c
