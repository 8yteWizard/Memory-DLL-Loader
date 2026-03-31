> ⚠️ Based on standard PE memory mapping techniques and inspired by the original MemoryModule project by Joachim Bauch: https://github.com/fancycode/MemoryModule

# Advanced Memory Loader (Delphi 12 Edition)

Native DLL loading from Disk, URL, or TCP without `LoadLibraryA` or other dependencies.

This is a pure Delphi 12 implementation of a fully-featured PE parser and memory mapper, supporting TLS, SEH, Delay-Load imports, and loading of DLL dependencies from memory in tandem.

---

![](/images/tcpdemo.png)
![](/images/httpdemo.png)
![](/images/diskdemo.png)

## Overview

The `UniversalLoader` client bypasses standard Windows disk-loading mechanisms (`LoadLibraryA`) by mapping raw DLL bytes directly into the process address space. It supports three ingestion methods:

1. Reads raw bytes from a local file path.
2. Downloads a DLL directly via HTTP/HTTPS using native `WinInet`.
3. Connects to a TCP server to receive DLL payloads over the network.
4. Intercepts dependency imports (optional) to load requirement DLLs entirely from memory.
5. Resolves the `Execute` export and runs the payload seamlessly.

This allows rapid deployment of modular applications, plugin systems, and fileless execution techniques in controlled environments.

---

## Features

- **Native Delphi 12 Implementation**: No external DLLs, Indy, or REST frameworks required.
- **Full PE Specification Support**: Handles TLS Callbacks, 64-bit SEH Registration, and Delay-Load Imports natively.
- **Export Forwarding Resolution**: Dynamically resolves forwarded exports (e.g., `NTDLL.RtlAllocateHeap`) on the fly.
- **O(log N) Binary Search**: Locates exported functions instantly using alphabetical binary search instead of linear looping.
- **Custom Dependency Resolvers**: Pass a callback to map child dependencies from memory instead of disk.
- **Event-Driven Logging**: Outputs color-coded, detailed stage-by-stage PE mapping logs to the console for easy debugging.
- **Anti-DoS & Overflow Protections**: Strict bounds checking on RVA, section sizes, and pointer arithmetic to prevent crashes from malformed PEs.

---

## Requirements

- Delphi 12 (or compatible RAD Studio version supporting `reference to` and `{$IFDEF WIN64}`)
- Windows 32-bit or 64-bit (Architecture of host MUST match the DLL being loaded)
- Standard Windows API (`kernel32.dll`, `ntdll.dll`, `wininet.dll`)
```text
No third-party packages are required to compile or run.
```

---

## Example Usage

### Interactive Client
```text
Client.exe

> 1

Enter DLL file path: C:\Plugins\Test.dll
```

### HTTP/HTTPS Download
```text
Client.exe

> 2

Enter DLL URL (http/https): http://192.168.1.10/payload.dll
```

### TCP Server Stream
```text
Client.exe

> 3

Enter Server IP (e.g., 127.0.0.1): 127.0.0.1
Enter Server Port: 4444
```

### Server Control
```text
Server.exe
=== TCP DLL Server ===
Listening on port 4444
Waiting for client connection...
Client connected!

Enter plugin name (without extension .dll, or "exit"):

> Test

[*] Found: C:\Test\Plugins\Test.dll
[*] Size: 55808 bytes
[*] Sending... OK
```

---

## Example Output

```text
======================================================
         Advanced Memory Loader Demo Client
======================================================

Select loading method:
  [1] Local File Path
  [2] Direct HTTP/HTTPS URL
  [3] TCP Server (IP/Port)
  [0] Exit
> 1

--- Mode: Local File ---
Enter DLL file path: Plugins\Test.dll

[*] Reading 55808 bytes from disk...
[*] Passing 55808 bytes to Memory Loader...
[LOADER INF] --------------------------------------------------
[LOADER INF] MemoryLoadLibrary: Starting PE Mapping Process...
[LOADER INF] Architecture validated: x86
[LOADER DBG] Preferred Base: 0x400000
[LOADER DBG] Image Size: 102400 bytes
[LOADER DBG] Memory reserved at: 0x400000
[LOADER DBG] Mapping 10 sections...
[LOADER DBG] Loaded at preferred base. Relocations skipped.
[LOADER INF] Resolving Standard Imports...
[LOADER DBG]   -> Resolving dependency: kernel32.dll
[LOADER DBG]   -> Resolving dependency: shell32.dll
[LOADER DBG]   -> Resolving dependency: oleaut32.dll
[LOADER INF] Resolving Delay-Load Imports (Eagerly)...
[LOADER DBG]   -> Resolving dependency: ´!@
[LOADER ERR] Failed to load dependency: ´!@
[LOADER DBG] Applying final section memory protections (RX/RW)...
[LOADER INF] Calling DllMain(DLL_PROCESS_ATTACH)...
[LOADER INF] --------------------------------------------------
[LOADER INF] SUCCESS: DLL mapped and initialized successfully!
[+] DLL loaded into memory successfully!
[LOADER DBG] Export "Execute" resolved -> 0x4094F8
[*] Calling Execute()...
[+] Execute() completed successfully.
[LOADER INF] MemoryFreeLibrary: Unloading module...
[LOADER DBG] Calling DllMain(DLL_PROCESS_DETACH)...
[LOADER DBG] Released CodeBase memory.
[LOADER INF] Module successfully unloaded.
[*] DLL unloaded from memory.
```

---

## How It Works

The `MemoryLoader.pas` engine bypasses the Windows Loader and manually reconstructs the PE image in RAM across 11 distinct stages:

| Stage | Action |
|-------|--------|
| 1-2   | Validates DOS/NT headers, ensures file is a DLL, and checks architecture (x86/x64) matches host. |
| 3-5   | Reserves memory (optimizing for preferred base address to skip relocations), commits sections, maps raw bytes. |
| 6     | Applies Base Relocations (HIGHLOW for x86, DIR64 for x64) if loaded at a different address. |
| 7     | Resolves Standard and Delay-Load Import Address Tables (IAT) via `GetProcAddress`. |
| 8     | Executes TLS Callbacks (required for C++ `thread_local` variables). |
| 9     | Registers 64-bit Exception Handling via `RtlAddFunctionTable` (prevents crashes on `__try`). |
| 10-11 | Applies final RX/RW memory protections, locks PE headers to Read-Only, calls `DllMain`. |

---

## Project Structure

Core components of the Delphi 12 implementation:

- `MemoryLoader.pas` — The core PE parsing engine. Handles allocations, relocations, imports, SEH, TLS, and exports.
- `UniversalLoader.dpr` — The interactive client. Implements the menu, file reading, `WinInet` downloading, and TCP socket receiving.
- `Server.dpr` — A lightweight TCP server that reads DLLs from a `Plugins\` folder and streams them to connected clients.
- `ProcessImportDescriptor` — Internal helper that processes both standard and delay-load thunk arrays safely.
- `SafeAddPtr` — Inline helper to prevent integer overflow exploits during pointer arithmetic.
- `CompareAnsiStr` — Local fast ANSI string comparer that bypasses Delphi 12 `SysUtils` deprecation warnings.

---

## Intended Use

- Plugin architectures (loading encrypted/compressed plugins from memory streams)
- Security research and malware analysis
- Bypassing disk-based monitoring and EDR sensors
- Fileless execution techniques

This tool is intended for defensive research, red team operations, and controlled lab environments only.

---

## Limitations

- **Architecture Strictness**: A 32-bit host cannot load a 64-bit DLL (this is a Windows limitation, not a bug).
- **Dependency Fallback**: By default, dependencies (like `vcruntime140.dll`) are still loaded from disk via `LoadLibraryA` unless a custom `TMemoryLoaderResolver` is implemented.
- **Resource Parsing**: Does not parse PE resource directories (not required for standard code execution).

---

> ⚠️ This readme (documentation) was generated with the assistance of AI.

> ⚠️ All code is human written.
