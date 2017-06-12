#! /bin/sh

exec clang -g -Weverything -dynamiclib -o c_hook.dylib c_hook.c
