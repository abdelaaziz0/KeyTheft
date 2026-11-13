# KeyTheft

**Fork of [ivancabrera02/KeyTheft](https://github.com/ivancabrera02/KeyTheft).**

KeyTheft dumps the Windows SAM database by stealing a registry KEY handle from the RemoteRegistry service's `svchost.exe` process and calling `NtSaveKey` on it. The attacking process never opens a SAM key itself. Output is XOR encrypted and disguised with a PNG header, so no `regf` magic bytes touch disk.

This fork fixes bugs that made the upstream release fail in practice: the C file did not compile, the PNG header failed CRC validation, and `sam_extract.py` produced wrong hashes on every Windows version. All fixes are verified on a live Windows 11 VM: `sam_extract.py` output is byte identical to `secretsdump.py`.

## Corrections

### KeyTheft.c

- Added the missing includes (`windows.h`, `stdio.h`, `stdlib.h`, `string.h`, `wchar.h`, `io.h`, `fcntl.h`). Upstream had none, so the file did not compile.
- Fixed the hardcoded PNG IHDR CRC. The stored value failed `zlib.crc32` validation, so every output file was a corrupt PNG.
- Check every `WriteFile` result before deleting the plaintext hive. Upstream could destroy the only copy of the data on a failed write.
- Bound the handle table allocation retry loop in `GetKeyTypeIndex` and initialize its `NTSTATUS`.
- Null terminate `_snwprintf` output buffers.
- Re enable a disabled RemoteRegistry service. On stock Windows 11 the service is Disabled and `StartService` fails with error 1058.
- Restore the service state after the run: stop it if we started it and restore the original start type.
- Stop the service through the signed `sc.exe`. On Windows 11, `ControlService(STOP)` returns `ACCESS_DENIED` for unsigned callers even with an elevated token and a `SERVICE_ALL_ACCESS` handle, while `StartService` and `ChangeServiceConfig` are allowed.
- Use the two call `NtQueryKey` pattern with a dynamically sized buffer instead of a fixed 2048 byte stack buffer.
- Skip handles without read access before calling `NtDuplicateObject`.
- Fall through to the next matching handle when `NtSaveKey` fails on one.
- Set UTF-8 output mode so console captures stay readable.
- Generate one random XOR key per output file instead of one shared key, and write each key to a `<output>.key` sidecar file.

### decode.py

- Replace the per byte XOR loop with a keystream XOR over big integers. Same output, orders of magnitude faster on the SYSTEM hive.

### sam_extract.py

- Fix the SAM revision mapping. Upstream treated revision 2 as RC4 and 3 as AES. The real values are 1 = RC4 and 2 = AES, so upstream hit the wrong branch on every system: legacy systems raised "Unknown SAM revision: 1" and modern systems decrypted garbage.
- Replace the incorrect `HMAC-MD5` per user key derivation with the correct plain `MD5(hashedBootKey[:16] + rid + "NTPASSWORD\0")` construction.
- Fix the `SAM_HASH_AES` blob parsing. Upstream read the revision from the `PekID` field and the salt from offset 4. The salt is at offset 8 and the encrypted hash at offset 24.
- Extract LM hashes. Upstream computed the offsets and never used them, printing the empty LM constant for every user.
- Verify the hashed boot key checksum, which detects Syskey startup passwords.
- Recurse `ri` index lists into `li` lists, upstream only handled `lf` and `lh` inside `ri` and silently missed subkeys.
- Add bounds checks to the hive parser so corrupt files raise a clean error instead of `struct.error`.

## Build

```bash
# MSVC
cl /W4 /O2 KeyTheft.c advapi32.lib

# MinGW / llvm-mingw
gcc -O2 -municode -o KeyTheft.exe KeyTheft.c -ladvapi32
```

## Usage

```
KeyTheft.exe [sam_output.png] [system_output.png]
```

Run from an elevated console. The tool starts RemoteRegistry if needed, dumps both hives, then returns the service to its original state.

### Decoding

Each output file has its own XOR key in a sidecar file:

```bash
python3 decode.py $(cat sam.png.key) sam.png
python3 decode.py $(cat system.png.key) system.png
```

### Hash extraction

```bash
secretsdump.py -sam sam.hiv -system system.hiv LOCAL
```

Or the standalone extractor (argument order: SAM first, SYSTEM second):

```bash
python3 sam_extract.py sam.hiv system.hiv
```

## Files

| File | Description |
|------|-------------|
| `KeyTheft.c` | Handle theft + XOR/PNG output |
| `KeyTheft.cs` | C# module: same chain as a single .NET 4 assembly, for `execute-assembly` or standalone use |
| `bof/KeyTheftBof.c` | Beacon Object File: same chain, runs inside the C2 agent process |
| `bof/beacon.h` | Minimal Beacon API declarations |
| `decode.py` | PNG to `.hiv` decoder |
| `sam_extract.py` | Standalone SAM hash extractor, matches `secretsdump.py` output |

## BOF

`bof/KeyTheftBof.c` compiles to a COFF object that runs inside the agent process. The whole chain is in-memory; only the hive dump (`NtSaveKey`) touches disk, and the plaintext `.tmp` is encrypted and removed in the same run.

```bash
# build (x64, no CRT, no linked imports)
x86_64-w64-mingw32-gcc -c -O2 -fno-builtin -o KeyTheftBof.x64.o KeyTheftBof.c
```

Agent invocation (the agent packs the argument string):

```
go p=<1|0> k=<0|1> sam=<path.png> sys=<path.png>
```

- `p=1` (default) XOR+PNG packs each file and prints the key per file; `p=0` renames the raw hive instead
- `k=1` keeps the plaintext `.tmp` on disk (testing only)
- `sam=` / `sys=` paths, use either or both

 Tested with [COFFLoader](https://github.com/trustedsec/COFFLoader) on Windows 11: handle theft, service re-enable/restore (signed `sc.exe` fallback), packing and boot key all verified; decoded output matches `secretsdump.py`.

## C# module

`KeyTheft.cs` is a C# port of the full chain for in-memory execution: no EXE lands on disk when loaded through a .NET capable agent. It also runs standalone.

```bash
csc /nologo /out:KeyTheftCS.exe KeyTheft.cs
KeyTheftCS.exe [--sam <path>] [--system <path>] [--pack png|none] [--keep-temp] [--quiet]
```

Differences from the C version:

- `--pack none` writes raw `.hiv` files, `--pack png` (default) applies the XOR/PNG disguise with one key per file.
- Exit codes: 0 both hives, 2 partial, 1 failure, 3 bad args.
- Keys and final status print to stdout even in `--quiet` mode.
- The service restore uses `ControlService` first and falls back to the signed `sc.exe` when the host process is unsigned and the target runs Windows 11.

## Requirements

- Windows 10 / 11, tested on Windows 11
- Administrator privileges (SeDebugPrivilege and SeBackupPrivilege)
- RemoteRegistry service installed (default, the tool re enables it if disabled and restores the start type afterwards)

## Notes

- On Windows 11 the RemoteRegistry service ships Disabled. The tool re enables it, dumps, and puts it back.
- `ControlService(STOP)` is denied to unsigned callers on Windows 11. This is why the restore path spawns the signed `sc.exe` binary.
- The XOR key for each file is written next to the output. It is not stored inside the PNG.

## Credits

Original technique and code by [ivancabrera02](https://github.com/ivancabrera02/KeyTheft). This fork only corrects bugs; see the Corrections section above. Hash extraction logic cross checked against [impacket](https://github.com/fortra/impacket).
