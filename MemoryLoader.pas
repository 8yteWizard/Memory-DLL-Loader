{
  ============================================================================
  @name        MemoryLoader
  @author      Byte Wizard
  @version     1.0.0.0
  @brief       Simple, easy, security-hardened DLL Memory Loader for Delphi.
  @github      https://github.com/8yteWizard

  Features:
    - Pure Delphi (No external dependencies)
    - Supports 32-bit and 64-bit DLLs natively
    - TLS (Thread Local Storage) Callback support
    - 64-bit SEH (Structured Exception Handling) registration
    - Resolves Standard & Delay-Load Imports
    - Resolves Export Forwarding dynamically
    - Import by Name or Ordinal
    - Anti-DoS & Integer Overflow protections
    - Highly detailed Event-Driven logging for easy debugging
  ============================================================================
}

unit MemoryLoader;

interface

uses
  Winapi.Windows,
  System.SysUtils;

// -----------------------------------------------------------------------------
// Log Levels for the callback system
// -----------------------------------------------------------------------------
type
  TLogLevel = (llDebug, llInfo, llWarning, llError);

  // Define the callback procedure type. Using 'reference to' allows
  // anonymous methods (lambda functions) to be assigned, which is very
  // modern and flexible for users implementing this unit.
  TMemoryLoaderLogEvent = reference to procedure(Level: TLogLevel; const Msg: string);

  // Define the callback type for custom dependency resolution
  TMemoryLoaderResolver = function(Name: PAnsiChar): HMODULE;

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

// Optional: Assign a logger to receive detailed debug/error messages.
// If this is not set, the loader runs silently.
procedure SetMemoryLoaderLogger(LogProc: TMemoryLoaderLogEvent);

/// <summary>
/// Loads a DLL from memory directly into the process address space.
/// </summary>
/// <param name="Data">Pointer to the raw DLL byte array (e.g., from a resource or stream).</param>
/// <param name="Size">Exact size of the DLL byte array in bytes.</param>
/// <param name="Resolver">Optional callback to intercept and resolve imports manually
/// (e.g., loading dependency DLLs from memory instead of disk). Pass nil for default LoadLibrary.</param>
/// <returns>A valid HMODULE handle on success, or 0 on failure.</returns>
function MemoryLoadLibrary(Data: Pointer; Size: NativeUInt; Resolver: TMemoryLoaderResolver = nil): HMODULE;

/// <summary>
/// Retrieves a function pointer from a memory-loaded module.
/// </summary>
/// <param name="Module">The HMODULE returned by MemoryLoadLibrary.</param>
/// <param name="Name">The ANSI name of the function, OR an Ordinal cast to PAnsiChar (e.g., PAnsiChar(Word(1))).</param>
/// <returns>The function pointer, or nil if not found.</returns>
function MemoryGetProcAddress(Module: HMODULE; Name: PAnsiChar): Pointer;

/// <summary>
/// Unloads a memory-loaded module, executing DllMain(DLL_PROCESS_DETACH)
/// and freeing all associated memory and OS tables.
/// </summary>
/// <param name="Module">The HMODULE to free.</param>
procedure MemoryFreeLibrary(Module: HMODULE);

implementation

// =============================================================================
// INTERNAL TYPES & CONSTANTS
// =============================================================================

type
  // Standard DllMain signature
  TDllEntryProc = function(hinstDLL: HMODULE; fdwReason: DWORD; lpReserved: Pointer): BOOL; stdcall;

  // TLS Callback signature (Executed before DllMain)
  TTLSCallbackProc = procedure(DllHandle: Pointer; Reason: DWORD; Reserved: Pointer); stdcall;

  PMemoryModule = ^TMemoryModule;
  TMemoryModule = record
    CodeBase: Pointer;       // Base address where the DLL was mapped in RAM
    ExportDirVA: DWORD;      // RVA of the Export Directory (for GetProcAddress)
    ExportDirSize: DWORD;    // Size of Export Directory
    Initialized: Boolean;    // Did DllMain(DLL_PROCESS_ATTACH) succeed?
    DllEntry: TDllEntryProc; // Cached pointer to DllMain
    SEHTable: Pointer;       // 64-bit: Pointer to the Exception table for cleanup
    SEHTableCount: DWORD;    // 64-bit: Number of entries in the exception table
  end;

  // The PE Relocation Block structure (Not fully defined in older Delphi headers)
  PImageBaseRelocation = ^TImageBaseRelocation;
  TImageBaseRelocation = packed record
    VirtualAddress: DWORD;   // The RVA where this block of relocations applies
    SizeOfBlock: DWORD;      // Total size of this block (header + entries)
  end;

  // TLS Directory structures for 32-bit and 64-bit
  PImageTlsDirectory32 = ^TImageTlsDirectory32;
  TImageTlsDirectory32 = packed record
    StartAddressOfRawData: DWORD;
    EndAddressOfRawData: DWORD;
    AddressOfIndex: DWORD;
    AddressOfCallBacks: DWORD; // Array of TTLSCallbackProc pointers, null terminated
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;

  PImageTlsDirectory64 = ^TImageTlsDirectory64;
  TImageTlsDirectory64 = packed record
    StartAddressOfRawData: UInt64;
    EndAddressOfRawData: UInt64;
    AddressOfIndex: UInt64;
    AddressOfCallBacks: UInt64;
    SizeOfZeroFill: DWORD;
    Characteristics: DWORD;
  end;

const
  // Relocation types: How to patch an address when the DLL is loaded at a different base
  IMAGE_REL_BASED_ABSOLUTE = 0; // Padding (does nothing)
  IMAGE_REL_BASED_HIGHLOW  = 3; // 32-bit: Patch all 4 bytes of an address
  IMAGE_REL_BASED_DIR64    = 10;// 64-bit: Patch all 8 bytes of an address

  // PE Characteristics flag: Ensures the file is a DLL, not an EXE
  IMAGE_FILE_DLL = $2000;

  // PE Header offsets to remove magic numbers and make code readable
  FILE_HDR_OFFSET = 4;  // Size of 'PE\0\0' signature
  OPT_HDR_OFFSET  = 24; // Signature(4) + FileHeader(20)

// =============================================================================
// INTERNAL VARIABLES & LOGGING SYSTEM
// =============================================================================

var
  LoggerProc: TMemoryLoaderLogEvent = nil;

procedure SetMemoryLoaderLogger(LogProc: TMemoryLoaderLogEvent);
begin
  LoggerProc := LogProc;
end;

// Helper to cleanly dispatch logs if a logger is assigned
procedure Log(Level: TLogLevel; const Msg: string);
begin
  if Assigned(LoggerProc) then
    LoggerProc(Level, Msg);
end;

// External NTDLL functions required to register 64-bit Structured Exception Handling
function RtlAddFunctionTable(FunctionTable: Pointer; EntryCount: DWORD; BaseAddress: UInt64): BOOL; stdcall; external 'ntdll.dll';
function RtlDeleteFunctionTable(FunctionTable: Pointer): BOOL; stdcall; external 'ntdll.dll';

// =============================================================================
// LOW-LEVEL SAFETY HELPERS
// =============================================================================

/// <summary>
/// Validates that a Data Directory RVA is safely within the allocated image.
/// Prevents reading unallocated memory from malformed PEs.
/// </summary>
function IsValidRVA(RVA: DWORD; DirSize: DWORD; ImageSize: NativeUInt): Boolean; inline;
begin
  Result := (RVA > 0) and (DirSize > 0) and (NativeUInt(RVA) + DirSize <= ImageSize);
end;

/// <summary>
/// Safe pointer arithmetic. If Base + Add exceeds the maximum pointer value,
/// it returns nil instead of wrapping around (which causes catastrophic bugs).
/// </summary>
function SafeAddPtr(Base: Pointer; Add: NativeUInt): Pointer; inline;
begin
  if (Add = 0) then Exit(Base);
  if NativeUInt(Base) > High(NativeUInt) - Add then Exit(nil);
  Result := Pointer(NativeUInt(Base) + Add);
end;

/// <summary>
/// Local fast ANSI string comparison.
/// Bypasses Delphi 12's messy SysUtils/AnsiStrings deprecation wars by doing
/// raw byte comparison. Very fast for binary searching export tables.
/// </summary>
function CompareAnsiStr(S1, S2: PAnsiChar): Integer;
var
  P1, P2: PByte;
begin
  P1 := PByte(S1);
  P2 := PByte(S2);
  while (P1^ <> 0) and (P1^ = P2^) do
  begin
    Inc(P1);
    Inc(P2);
  end;
  Result := Integer(P1^) - Integer(P2^);
end;

// =============================================================================
// IMPORT RESOLVER ENGINE
// =============================================================================

/// <summary>
/// Centralized logic to process Import Descriptor arrays.
/// Handles both Standard (IMAGE_DIRECTORY_ENTRY_IMPORT) and
/// Delay-Load (IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) directories.
/// </summary>
procedure ProcessImportDescriptor(Module: PMemoryModule; ImportDesc: PImageImportDescriptor;
  CodeBase: Pointer; ImageSize: NativeUInt; Is64: Boolean; Resolver: TMemoryLoaderResolver);
var
  ImportName: PAnsiChar;
  ImportedModule: HMODULE;
  ThunkRef, FuncRef: PNativeUInt;
  FuncAddr: Pointer;
  ThunkValue: NativeUInt;
  ThunkEnd: Pointer;
begin
  // Calculate absolute maximum boundary to prevent infinite loops if
  // the OriginalFirstThunk array is corrupted and never hits a null terminator.
  ThunkEnd := SafeAddPtr(CodeBase, ImageSize);

  while (ImportDesc^.Name <> 0) and (ImportDesc^.Name < ImageSize) do
  begin
    ImportName := PAnsiChar(SafeAddPtr(CodeBase, ImportDesc^.Name));
    if ImportName = nil then Break;

    Log(llDebug, Format('  -> Resolving dependency: %s', [String(AnsiString(ImportName))]));

    // Ask the user's custom resolver first, otherwise fallback to Windows disk loader
    if Assigned(Resolver) then
      ImportedModule := Resolver(ImportName)
    else
      ImportedModule := LoadLibraryA(ImportName);

    if ImportedModule = 0 then
    begin
      Log(llError, Format('Failed to load dependency: %s', [String(AnsiString(ImportName))]));
      Exit;
    end;

    // OriginalFirstThunk points to the unmodified Hint/Name array (preferred).
    // If it's missing, fallback to FirstThunk.
    if ImportDesc^.OriginalFirstThunk <> 0 then
      ThunkRef := PNativeUInt(SafeAddPtr(CodeBase, ImportDesc^.OriginalFirstThunk))
    else
      ThunkRef := PNativeUInt(SafeAddPtr(CodeBase, ImportDesc^.FirstThunk));

    // FirstThunk is where we write the actual resolved memory addresses
    FuncRef := PNativeUInt(SafeAddPtr(CodeBase, ImportDesc^.FirstThunk));

    // Iterate through the thunk array
    while (ThunkRef <> nil) and (FuncRef <> nil) and
          (NativeUInt(ThunkRef) < NativeUInt(ThunkEnd)) and (ThunkRef^ <> 0) do
    begin
      ThunkValue := ThunkRef^;

      {$IFDEF WIN64}
        // If the highest bit is set, this is an Import by Ordinal (ID number), not a string
        if (ThunkValue and IMAGE_ORDINAL_FLAG64) <> 0 then
        begin
          Log(llDebug, Format('     Resolving by Ordinal: %d', [ThunkValue and $FFFF]));
          FuncAddr := GetProcAddress(ImportedModule, PAnsiChar(ThunkValue and $FFFF))
        end
        else
      {$ELSE}
        if (ThunkValue and IMAGE_ORDINAL_FLAG32) <> 0 then
        begin
          Log(llDebug, Format('     Resolving by Ordinal: %d', [ThunkValue and $FFFF]));
          FuncAddr := GetProcAddress(ImportedModule, PAnsiChar(ThunkValue and $FFFF))
        end
        else
      {$ENDIF}
        begin
          // It's an Import by Name. The structure is:
          // [WORD Hint] [CHAR[] Name]
          // We skip the 2-byte Hint by adding 2 to the pointer.
          FuncAddr := GetProcAddress(ImportedModule,
            PAnsiChar(SafeAddPtr(CodeBase, ThunkValue + 2)));
        end;

      if FuncAddr = nil then
      begin
        Log(llError, 'Failed to resolve a specific function inside a dependency.');
        Exit;
      end;

      // Patch the Import Address Table (IAT) with the real memory address
      FuncRef^ := NativeUInt(FuncAddr);
      Inc(ThunkRef);
      Inc(FuncRef);
    end;
    Inc(ImportDesc);
  end;
end;

// =============================================================================
// MAIN LOADER LOGIC
// =============================================================================

function MemoryLoadLibrary(Data: Pointer; Size: NativeUInt; Resolver: TMemoryLoaderResolver): HMODULE;
var
  DOSHeader: PImageDosHeader;
  NtHeadersPtr: Pointer;
  FileHeader: PImageFileHeader;
  OptHeader32: PImageOptionalHeader32;
  OptHeader64: PImageOptionalHeader64;
  DllDir: PImageDataDirectory;
  Section: PImageSectionHeader;
  CodeBase: Pointer;
  HeadersSize, ImageSize: NativeUInt;
  LocationDelta: NativeInt;
  i: Integer;
  Module: PMemoryModule;
  Reloc: PImageBaseRelocation;
  RelocCount: DWORD;
  RelocInfo: PWORD;
  ImportDesc: PImageImportDescriptor;
  DllEntry: TDllEntryProc;
  OldProtect: DWORD;
  Protect: DWORD;
  BaseOfDll: NativeUInt;
  EntryPoint: NativeUInt;
  RelocAddr: PNativeUInt;
  Is64: Boolean;
  Success: Boolean;
  SectionSize: NativeUInt;
  RelocType: Word;
  Lfanew: Integer;
  CallbackPtr: PNativeUInt;
  CallbackFunc: TTLSCallbackProc;
  SEHTablePtr: Pointer;
begin
  Result := 0;
  Module := nil;
  CodeBase := nil;
  Success := False;

  Log(llInfo, '--------------------------------------------------');
  Log(llInfo, 'MemoryLoadLibrary: Starting PE Mapping Process...');

  // ---------------------------------------------------------
  // STAGE 1: Initial Buffer Safety Checks
  // ---------------------------------------------------------
  if (Data = nil) or (Size = 0) then
  begin
    Log(llError, 'Invalid input: Data is nil or Size is 0.');
    Exit;
  end;

  try
    DOSHeader := PImageDosHeader(Data);
    if DOSHeader^.e_magic <> IMAGE_DOS_SIGNATURE then
    begin
      Log(llError, 'Invalid DOS Header signature (Not an MZ file).');
      Exit;
    end;

    // Delphi 32-bit uses an underscore for lfanew, 64-bit does not. This unifies it.
    {$IF Defined(CPUX86)}
      Lfanew := DOSHeader^._lfanew;
    {$ELSE}
      Lfanew := DOSHeader^.e_lfanew;
    {$IFEND}

    // The lfanew offset must be positive and aligned to 8 bytes per PE spec
    if (Lfanew < 0) or ((Lfanew and $7) <> 0) then
    begin
      Log(llError, Format('Invalid lfanew offset or alignment: %d', [Lfanew]));
      Exit;
    end;

    // Ensure we don't read past the buffer when checking the PE signature
    if NativeUInt(Lfanew) + SizeOf(DWORD) > Size then
    begin
      Log(llError, 'File truncated: lfanew points past end of buffer.');
      Exit;
    end;

    NtHeadersPtr := SafeAddPtr(Data, Lfanew);
    FileHeader := PImageFileHeader(SafeAddPtr(NtHeadersPtr, FILE_HDR_OFFSET));

    if PWord(NtHeadersPtr)^ <> IMAGE_NT_SIGNATURE then
    begin
      Log(llError, 'Invalid NT Header signature (Not a PE file).');
      Exit;
    end;

    // ---------------------------------------------------------
    // STAGE 2: PE Architecture Validation
    // ---------------------------------------------------------
    if (OPT_HDR_OFFSET + FileHeader^.SizeOfOptionalHeader) > Size then
    begin
      Log(llError, 'Optional Header size exceeds file buffer.');
      Exit;
    end;

    OptHeader32 := PImageOptionalHeader32(SafeAddPtr(NtHeadersPtr, OPT_HDR_OFFSET));

    // Reject EXEs. This loader is designed strictly for DLLs.
    if (FileHeader^.Characteristics and IMAGE_FILE_DLL) = 0 then
    begin
      Log(llError, 'File is an EXE, not a DLL. Rejected.');
      Exit;
    end;

    // Ensure the DLL architecture matches the host application architecture
    {$IFDEF WIN64}
      if OptHeader32^.Magic <> IMAGE_NT_OPTIONAL_HDR64_MAGIC then
      begin
        Log(llError, 'Architecture mismatch: Expected 64-bit DLL in 64-bit app.');
        Exit;
      end;
      Is64 := True;
    {$ELSE}
      if OptHeader32^.Magic <> IMAGE_NT_OPTIONAL_HDR32_MAGIC then
      begin
        Log(llError, 'Architecture mismatch: Expected 32-bit DLL in 32-bit app.');
        Exit;
      end;
      Is64 := False;
    {$ENDIF}

    // Fixed: Avoids System.StrUtils dependency by using standard if/else
    if Is64 then
      Log(llInfo, 'Architecture validated: x64')
    else
      Log(llInfo, 'Architecture validated: x86');

    // ---------------------------------------------------------
    // STAGE 3: Extract Image Metrics
    // ---------------------------------------------------------
    if Is64 then
    begin
      OptHeader64 := PImageOptionalHeader64(OptHeader32);
      ImageSize    := OptHeader64^.SizeOfImage;
      BaseOfDll    := OptHeader64^.ImageBase;
      EntryPoint   := OptHeader64^.AddressOfEntryPoint;
      HeadersSize  := OptHeader64^.SizeOfHeaders;
    end
    else
    begin
      ImageSize    := OptHeader32^.SizeOfImage;
      BaseOfDll    := OptHeader32^.ImageBase;
      EntryPoint   := OptHeader32^.AddressOfEntryPoint;
      HeadersSize  := OptHeader32^.SizeOfHeaders;
    end;

    if ImageSize = 0 then
    begin
      Log(llError, 'SizeOfImage is 0.');
      Exit;
    end;
    if HeadersSize = 0 then HeadersSize := 4096;

    Log(llDebug, Format('Preferred Base: 0x%x', [BaseOfDll]));
    Log(llDebug, Format('Image Size: %d bytes', [ImageSize]));

    // ---------------------------------------------------------
    // STAGE 4: Memory Allocation (Base Optimization)
    // ---------------------------------------------------------
    // Try to allocate exactly where the DLL wants to be. If successful,
    // we skip the heavy relocation patching process entirely (huge speed boost).
    CodeBase := VirtualAlloc(Pointer(BaseOfDll), ImageSize, MEM_RESERVE, PAGE_NOACCESS);
    if CodeBase = nil then
    begin
      Log(llDebug, 'Preferred base occupied, falling back to ASLR random allocation.');
      CodeBase := VirtualAlloc(nil, ImageSize, MEM_RESERVE, PAGE_NOACCESS);
    end;

    if CodeBase = nil then
    begin
      Log(llError, 'Out of memory: Could not reserve virtual memory space.');
      Exit;
    end;

    Log(llDebug, Format('Memory reserved at: 0x%x', [NativeUInt(CodeBase)]));

    Module := AllocMem(SizeOf(TMemoryModule));
    Module^.CodeBase := CodeBase;

    // Commit the headers and copy them over
    if VirtualAlloc(CodeBase, HeadersSize, MEM_COMMIT, PAGE_READWRITE) = nil then
    begin
      Log(llError, 'Failed to commit memory for PE headers.');
      Exit;
    end;
    Move(Data^, CodeBase^, HeadersSize);

    // ---------------------------------------------------------
    // STAGE 5: Map Section Data
    // ---------------------------------------------------------
    Section := PImageSectionHeader(SafeAddPtr(NtHeadersPtr, OPT_HDR_OFFSET + FileHeader^.SizeOfOptionalHeader));

    // Protect against DoS: Max sections allowed in PE spec is 96
    if FileHeader^.NumberOfSections > 96 then
    begin
      Log(llError, Format('DoS Protection: Too many sections declared (%d).', [FileHeader^.NumberOfSections]));
      Exit;
    end;

    Log(llDebug, Format('Mapping %d sections...', [FileHeader^.NumberOfSections]));
    for i := 0 to FileHeader^.NumberOfSections - 1 do
    begin
      if Section = nil then Exit;

      // Validate that raw data doesn't exceed our buffer, and virtual size doesn't exceed image
      if (NativeUInt(Section^.PointerToRawData) + Section^.SizeOfRawData > Size) or
         (NativeUInt(Section^.VirtualAddress) + Section^.Misc.VirtualSize > ImageSize) then
      begin
        Log(llError, Format('Section %d bounds check failed.', [i]));
        Exit;
      end;

      // VirtualSize can be 0 in poorly compiled DLLs. Fallback to SizeOfRawData.
      SectionSize := Section^.Misc.VirtualSize;
      if SectionSize = 0 then SectionSize := Section^.SizeOfRawData;

      if SectionSize > 0 then
      begin
        if VirtualAlloc(SafeAddPtr(CodeBase, Section^.VirtualAddress),
          SectionSize, MEM_COMMIT, PAGE_READWRITE) = nil then
        begin
          Log(llError, Format('Failed to commit memory for Section %d.', [i]));
          Exit;
        end;

        if Section^.SizeOfRawData > 0 then
        begin
          Move(Pointer(SafeAddPtr(Data, Section^.PointerToRawData))^,
            Pointer(SafeAddPtr(CodeBase, Section^.VirtualAddress))^,
            Section^.SizeOfRawData);

          // Zero out the difference between file size and RAM size (Uninitialized BSS data)
          if SectionSize > Section^.SizeOfRawData then
            ZeroMemory(Pointer(SafeAddPtr(CodeBase, Section^.VirtualAddress + Section^.SizeOfRawData)),
              SectionSize - Section^.SizeOfRawData);
        end
        else
          ZeroMemory(Pointer(SafeAddPtr(CodeBase, Section^.VirtualAddress)), SectionSize);
      end;
      Inc(Section);
    end;

    // ---------------------------------------------------------
    // STAGE 6: Process Base Relocations
    // ---------------------------------------------------------
    LocationDelta := NativeInt(CodeBase) - NativeInt(BaseOfDll);

    if LocationDelta <> 0 then
    begin
      Log(llInfo, Format('Applying Relocations (Delta: 0x%x)...', [LocationDelta]));

      if Is64 then DllDir := @OptHeader64^.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
      else DllDir := @OptHeader32^.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

      if IsValidRVA(DllDir^.VirtualAddress, DllDir^.Size, ImageSize) then
      begin
        Reloc := PImageBaseRelocation(SafeAddPtr(CodeBase, DllDir^.VirtualAddress));

        while (NativeUInt(Reloc) < NativeUInt(CodeBase) + DllDir^.VirtualAddress + DllDir^.Size)
          and (Reloc^.SizeOfBlock >= SizeOf(TImageBaseRelocation)) do
        begin
          if NativeUInt(Reloc) + Reloc^.SizeOfBlock >
             NativeUInt(CodeBase) + DllDir^.VirtualAddress + DllDir^.Size then Break;

          // Each block has a header, followed by an array of 16-bit entries
          RelocCount := (Reloc^.SizeOfBlock - SizeOf(TImageBaseRelocation)) div 2;
          RelocInfo := PWORD(SafeAddPtr(Reloc, SizeOf(TImageBaseRelocation)));

          for i := 0 to Integer(RelocCount) - 1 do
          begin
            // Top 4 bits = relocation type, bottom 12 bits = RVA offset
            RelocType := RelocInfo^ shr 12;

            if Is64 then
            begin
              if RelocType = IMAGE_REL_BASED_DIR64 then
              begin
                RelocAddr := PNativeUInt(SafeAddPtr(CodeBase, Reloc^.VirtualAddress + (RelocInfo^ and $0FFF)));
                if RelocAddr <> nil then RelocAddr^ := RelocAddr^ + NativeUInt(LocationDelta);
              end
              else if RelocType <> IMAGE_REL_BASED_ABSOLUTE then Exit; // Unknown type
            end
            else
            begin
              if RelocType = IMAGE_REL_BASED_HIGHLOW then
              begin
                RelocAddr := PNativeUInt(SafeAddPtr(CodeBase, Reloc^.VirtualAddress + (RelocInfo^ and $0FFF)));
                if RelocAddr <> nil then RelocAddr^ := RelocAddr^ + NativeUInt(LocationDelta);
              end
              else if RelocType <> IMAGE_REL_BASED_ABSOLUTE then Exit; // Unknown type
            end;
            Inc(RelocInfo);
          end;
          Reloc := PImageBaseRelocation(SafeAddPtr(Reloc, Reloc^.SizeOfBlock));
        end;
      end;
    end
    else
      Log(llDebug, 'Loaded at preferred base. Relocations skipped.');

    // ---------------------------------------------------------
    // STAGE 7: Resolve Imports (Standard & Delay-Load)
    // ---------------------------------------------------------
    Log(llInfo, 'Resolving Standard Imports...');
    if Is64 then DllDir := @OptHeader64^.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
    else DllDir := @OptHeader32^.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if IsValidRVA(DllDir^.VirtualAddress, DllDir^.Size, ImageSize) then
    begin
      ImportDesc := PImageImportDescriptor(SafeAddPtr(CodeBase, DllDir^.VirtualAddress));
      ProcessImportDescriptor(Module, ImportDesc, CodeBase, ImageSize, Is64, Resolver);
    end;

    // Delay-Load imports: We resolve them eagerly here to avoid needing complex
    // executable assembly thunk stubs that intercept Windows loader delays.
    Log(llInfo, 'Resolving Delay-Load Imports (Eagerly)...');
    if Is64 then DllDir := @OptHeader64^.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]
    else DllDir := @OptHeader32^.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];

    if IsValidRVA(DllDir^.VirtualAddress, DllDir^.Size, ImageSize) then
    begin
      ImportDesc := PImageImportDescriptor(SafeAddPtr(CodeBase, DllDir^.VirtualAddress));
      ProcessImportDescriptor(Module, ImportDesc, CodeBase, ImageSize, Is64, Resolver);
    end;

    // ---------------------------------------------------------
    // STAGE 8: Execute TLS Callbacks
    // ---------------------------------------------------------
    // TLS callbacks MUST run before DllMain. C++ `thread_local` variables rely on this.
    if Is64 then DllDir := @OptHeader64^.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]
    else DllDir := @OptHeader32^.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if IsValidRVA(DllDir^.VirtualAddress, DllDir^.Size, ImageSize) then
    begin
      Log(llInfo, 'Executing TLS Callbacks...');
      if Is64 then
        CallbackPtr := PNativeUInt(PImageTlsDirectory64(SafeAddPtr(CodeBase, DllDir^.VirtualAddress))^.AddressOfCallBacks)
      else
        CallbackPtr := PNativeUInt(PImageTlsDirectory32(SafeAddPtr(CodeBase, DllDir^.VirtualAddress))^.AddressOfCallBacks);

      // The callback array is terminated by a null pointer
      while (CallbackPtr <> nil) and (CallbackPtr^ <> 0) do
      begin
        CallbackFunc := TTLSCallbackProc(CallbackPtr^);
        Log(llDebug, Format('  -> Calling TLS Callback at 0x%x', [CallbackPtr^]));
        CallbackFunc(CodeBase, DLL_PROCESS_ATTACH, nil);
        Inc(CallbackPtr);
      end;
    end;

    // ---------------------------------------------------------
    // STAGE 9: Register 64-bit Exception Handling (SEH)
    // ---------------------------------------------------------
    {$IFDEF WIN64}
    if Is64 then
    begin
      DllDir := @OptHeader64^.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
      if IsValidRVA(DllDir^.VirtualAddress, DllDir^.Size, ImageSize) then
      begin
        SEHTablePtr := SafeAddPtr(CodeBase, DllDir^.VirtualAddress);
        Module^.SEHTableCount := DllDir^.Size div SizeOf(TImageRuntimeFunctionEntry);
        if Module^.SEHTableCount > 0 then
        begin
          Module^.SEHTable := SEHTablePtr;
          RtlAddFunctionTable(SEHTablePtr, Module^.SEHTableCount, UInt64(CodeBase));
          Log(llInfo, Format('Registered %d 64-bit SEH entries.', [Module^.SEHTableCount]));
        end;
      end;
    end;
    {$ENDIF}

    // ---------------------------------------------------------
    // STAGE 10: Apply Final Memory Protections
    // ---------------------------------------------------------
    Log(llDebug, 'Applying final section memory protections (RX/RW)...');
    Section := PImageSectionHeader(SafeAddPtr(NtHeadersPtr, OPT_HDR_OFFSET + FileHeader^.SizeOfOptionalHeader));
    for i := 0 to FileHeader^.NumberOfSections - 1 do
    begin
      if Section = nil then Break;
      if Section^.Misc.VirtualSize > 0 then
      begin
        Protect := PAGE_NOACCESS;
        // Translate PE Section flags to Windows VirtualProtect flags
        if (Section^.Characteristics and IMAGE_SCN_MEM_EXECUTE) <> 0 then
        begin
          if (Section^.Characteristics and IMAGE_SCN_MEM_READ) <> 0 then
          begin
            if (Section^.Characteristics and IMAGE_SCN_MEM_WRITE) <> 0 then Protect := PAGE_EXECUTE_READWRITE
            else Protect := PAGE_EXECUTE_READ;
          end
          else Protect := PAGE_EXECUTE;
        end
        else if (Section^.Characteristics and IMAGE_SCN_MEM_READ) <> 0 then
        begin
          if (Section^.Characteristics and IMAGE_SCN_MEM_WRITE) <> 0 then Protect := PAGE_READWRITE
          else Protect := PAGE_READONLY;
        end
        else if (Section^.Characteristics and IMAGE_SCN_MEM_WRITE) <> 0 then
          Protect := PAGE_READWRITE;

        if Protect <> PAGE_NOACCESS then
          VirtualProtect(SafeAddPtr(CodeBase, Section^.VirtualAddress),
            Section^.Misc.VirtualSize, Protect, @OldProtect);
      end;
      Inc(Section);
    end;

    // Lock down headers to Read-Only for security hardening
    VirtualProtect(CodeBase, HeadersSize, PAGE_READONLY, @OldProtect);

    // ---------------------------------------------------------
    // STAGE 11: Cache Exports & Execute DllMain
    // ---------------------------------------------------------
    if Is64 then DllDir := @OptHeader64^.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
    else DllDir := @OptHeader32^.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    Module^.ExportDirVA := DllDir^.VirtualAddress;
    Module^.ExportDirSize := DllDir^.Size;

    if EntryPoint <> 0 then
    begin
      Log(llInfo, 'Calling DllMain(DLL_PROCESS_ATTACH)...');
      DllEntry := TDllEntryProc(SafeAddPtr(CodeBase, EntryPoint));
      Module^.DllEntry := DllEntry;

      if not DllEntry(NativeUInt(CodeBase), DLL_PROCESS_ATTACH, nil) then
      begin
        Log(llError, 'DllMain returned FALSE! Initialization failed.');
        Exit;
      end;
    end
    else
      Log(llWarning, 'DLL has no EntryPoint.');

    Module^.Initialized := True;
    Result := HMODULE(Module);
    Success := True;

    Log(llInfo, '--------------------------------------------------');
    Log(llInfo, 'SUCCESS: DLL mapped and initialized successfully!');

  finally
    // If ANY step failed, Success will be false, and we must clean up
    // partially allocated memory to prevent leaks.
    if not Success then
    begin
      Log(llError, 'Cleaning up failed load attempt...');
      if Module <> nil then FreeMem(Module);
      if CodeBase <> nil then VirtualFree(CodeBase, 0, MEM_RELEASE);
    end;
  end;
end;

// =============================================================================
// GET PROC ADDRESS (With Binary Search & Forwarding)
// =============================================================================

function MemoryGetProcAddress(Module: HMODULE; Name: PAnsiChar): Pointer;
var
  MemModule: PMemoryModule;
  ExportTable: PImageExportDirectory;
  Lo, Hi, Mid, Cmp: Integer;
  ExportName: PAnsiChar;
  Ordinal: Word;
  FuncRVA: DWORD;
  NameRVA: DWORD;
  ForwardStr: PAnsiChar;
  ForwardMod: HMODULE;
  P: PAnsiChar;
  DllName, FuncName: AnsiString;
  PStart, PEnd: PAnsiChar; // Used to manually calculate string length
begin
  Result := nil;
  if Module = 0 then Exit;

  MemModule := PMemoryModule(Module);
  if MemModule^.ExportDirSize = 0 then Exit;

  ExportTable := PImageExportDirectory(SafeAddPtr(MemModule^.CodeBase, MemModule^.ExportDirVA));
  if ExportTable = nil then Exit;

  // Feature: Support Import by Ordinal (High word is 0, low word is ID)
  if (NativeUInt(Name) <= $FFFF) then
  begin
    Ordinal := Word(Name) - ExportTable^.Base;
    if Ordinal < ExportTable^.NumberOfFunctions then
    begin
      FuncRVA := PDWORD(SafeAddPtr(MemModule^.CodeBase,
        ExportTable^.AddressOfFunctions + NativeUInt(Ordinal) * SizeOf(DWORD)))^;
      Result := SafeAddPtr(MemModule^.CodeBase, FuncRVA);
      Log(llDebug, Format('Export resolved by Ordinal (%d) -> 0x%x', [Word(Name), NativeUInt(Result)]));
    end;
    Exit;
  end;

  // Feature: Binary Search. PE spec guarantees export names are sorted alphabetically.
  // This drops lookup time from O(N) to O(log N).
  Lo := 0;
  Hi := ExportTable^.NumberOfNames - 1;

  while Lo <= Hi do
  begin
    Mid := (Lo + Hi) shr 1;

    NameRVA := PDWORD(SafeAddPtr(MemModule^.CodeBase,
      ExportTable^.AddressOfNames + NativeUInt(Mid) * SizeOf(DWORD)))^;

    ExportName := PAnsiChar(SafeAddPtr(MemModule^.CodeBase, NameRVA));
    Cmp := CompareAnsiStr(ExportName, Name);

    if Cmp = 0 then
    begin
      // Found the name! Now get the matching ordinal
      Ordinal := PWord(SafeAddPtr(MemModule^.CodeBase,
        ExportTable^.AddressOfNameOrdinals + NativeUInt(Mid) * SizeOf(Word)))^;

      FuncRVA := PDWORD(SafeAddPtr(MemModule^.CodeBase,
        ExportTable^.AddressOfFunctions + NativeUInt(Ordinal) * SizeOf(DWORD)))^;

      // Feature: Export Forwarding Detection
      // If the function RVA points INSIDE the export directory, it's not code.
      // It's a null-terminated string like "NTDLL.RtlAllocateHeap"
      if (FuncRVA >= MemModule^.ExportDirVA) and
         (FuncRVA < MemModule^.ExportDirVA + MemModule^.ExportDirSize) then
      begin
        ForwardStr := PAnsiChar(SafeAddPtr(MemModule^.CodeBase, FuncRVA));
        Log(llWarning, Format('Export is Forwarded -> %s', [String(AnsiString(ForwardStr))]));

        // Safely parse the string into native Delphi strings (avoiding memory modification)
        P := ForwardStr;
        while (P^ <> #0) and (P^ <> '.') do Inc(P);

        if P^ = '.' then
        begin
          SetString(DllName, ForwardStr, P - ForwardStr);

          // Fixed: Replaced deprecated StrLen with raw pointer math to avoid warnings
          PStart := PAnsiChar(NativeUInt(P) + 1);
          PEnd := PStart;
          while PEnd^ <> #0 do Inc(PEnd);
          SetString(FuncName, PStart, PEnd - PStart);

          ForwardMod := LoadLibraryA(PAnsiChar(DllName));
          if ForwardMod <> 0 then
            Result := GetProcAddress(ForwardMod, PAnsiChar(FuncName));
        end;
        Exit;
      end;

      Result := SafeAddPtr(MemModule^.CodeBase, FuncRVA);
      Log(llDebug, Format('Export "%s" resolved -> 0x%x', [String(AnsiString(Name)), NativeUInt(Result)]));
      Exit;
    end
    else if Cmp < 0 then Lo := Mid + 1
    else Hi := Mid - 1;
  end;

  Log(llWarning, Format('Export "%s" not found.', [String(AnsiString(Name))]));
end;

// =============================================================================
// FREE LIBRARY (Cleanup & SEH Unregister)
// =============================================================================

procedure MemoryFreeLibrary(Module: HMODULE);
var
  MemModule: PMemoryModule;
begin
  if Module = 0 then Exit;
  MemModule := PMemoryModule(Module);

  Log(llInfo, 'MemoryFreeLibrary: Unloading module...');

  // Exception Safety: If the loaded DLL throws an Access Violation or Delphi
  // exception during detach, we MUST catch it so we can still free the memory.
  if MemModule^.Initialized and Assigned(MemModule^.DllEntry) then
  begin
    try
      Log(llDebug, 'Calling DllMain(DLL_PROCESS_DETACH)...');
      MemModule^.DllEntry(NativeUInt(MemModule^.CodeBase), DLL_PROCESS_DETACH, nil);
    except
      on E: Exception do
        Log(llError, Format('Exception during DLL_PROCESS_DETACH: %s', [E.Message]));
    end;
  end;

  // Cleanup 64-bit Exception tables so Windows doesn't call freed memory on crashes
  {$IFDEF WIN64}
  if MemModule^.SEHTable <> nil then
  begin
    RtlDeleteFunctionTable(MemModule^.SEHTable);
    Log(llDebug, 'Unregistered 64-bit SEH table.');
  end;
  {$ENDIF}

  if MemModule^.CodeBase <> nil then
  begin
    VirtualFree(MemModule^.CodeBase, 0, MEM_RELEASE);
    Log(llDebug, 'Released CodeBase memory.');
  end;

  FreeMem(MemModule);
  Log(llInfo, 'Module successfully unloaded.');
end;

end.
