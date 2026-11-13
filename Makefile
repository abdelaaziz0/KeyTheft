MINGW ?= x86_64-w64-mingw32-gcc
STUB ?= tests/winstub
PY ?= python3

.PHONY: all stub-check test clean

all: KeyTheft.exe bof/KeyTheftBof.x64.o

stub-check:
	gcc -std=gnu11 -fsyntax-only -Wno-unknown-pragmas -I $(STUB) KeyTheft.c

KeyTheft.exe: KeyTheft.c stub-check
	$(MINGW) -municode -static -O2 -o $@ $< -ladvapi32

bof/KeyTheftBof.x64.o: bof/KeyTheftBof.c bof/beacon.h
	$(MINGW) -c -O2 -fno-builtin -o $@ $<

test: py-compile unit

py-compile:
	$(PY) -m py_compile decode.py sam_extract.py

unit:
	$(PY) tests/run_tests.py

clean:
	rm -f KeyTheft.exe bof/KeyTheftBof.x64.o
	rm -rf __pycache__ tests/__pycache__
