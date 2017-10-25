SHELL := /bin/sh
GCC := gcc

abnf: abnf.c
	$(GCC) -o $@ $+
