#! /bin/sh

exec clang -g -Weverything -Wno-incompatible-pointer-types-discards-qualifiers -dynamiclib -o master.dylib c_hook.c
