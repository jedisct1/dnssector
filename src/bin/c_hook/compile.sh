#! /bin/sh

exec clang -g -Weverything -Wno-incompatible-pointer-types-discards-qualifiers -dynamiclib -o c_hook.dylib c_hook.c
