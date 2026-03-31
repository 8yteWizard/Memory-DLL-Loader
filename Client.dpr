program UniversalLoader;

{$APPTYPE CONSOLE}
{$ALIGN 8}

uses
  System.SysUtils,
  System.Classes,
  Winapi.Windows,
  Winapi.Winsock2,
  Winapi.WinInet,
  MemoryLoader in 'MemoryLoader.pas';

type
  TExecuteProc = procedure; stdcall;

// =============================================================================
// CONSOLE HELPERS
// =============================================================================

procedure SetConsoleColor(Color: Word);
var
  ConsoleInfo: TConsoleScreenBufferInfo;
  StdOut: THandle;
begin
  StdOut := GetStdHandle(STD_OUTPUT_HANDLE);
  if GetConsoleScreenBufferInfo(StdOut, ConsoleInfo) then
    SetConsoleTextAttribute(StdOut, Color);
end;

procedure PrintHeader;
begin
  SetConsoleColor($0B);
  Writeln('======================================================');
  Writeln('         Advanced Memory Loader Demo Client');
  Writeln('======================================================');
  SetConsoleColor($07);
  Writeln;
end;

// =============================================================================
// MEMORY LOADER LOGGING SETUP
// =============================================================================

procedure SetupLoaderLogging;
begin
  SetMemoryLoaderLogger(
    procedure(Level: TLogLevel; const Msg: string)
    begin
      case Level of
        llDebug:   begin SetConsoleColor($08); Write('[LOADER DBG] '); end;
        llInfo:    begin SetConsoleColor($0B); Write('[LOADER INF] '); end;
        llWarning: begin SetConsoleColor($0E); Write('[LOADER WRN] '); end;
        llError:   begin SetConsoleColor($0C); Write('[LOADER ERR] '); end;
      end;
      Writeln(Msg);
      SetConsoleColor($07);
    end
  );
end;

// =============================================================================
// EXECUTION ENGINE
// =============================================================================

procedure ExecuteFromMemory(Data: Pointer; Size: NativeUInt);
var
  Module: HMODULE;
  ExecProc: TExecuteProc;
begin
  Writeln('[*] Passing ', Size, ' bytes to Memory Loader...');
  Module := MemoryLoadLibrary(Data, Size, nil);

  if Module = 0 then
  begin
    SetConsoleColor($0C);
    Writeln('[!] MemoryLoadLibrary failed (check loader logs above for reason)');
    SetConsoleColor($07);
    Exit;
  end;

  SetConsoleColor($0A);
  Writeln('[+] DLL loaded into memory successfully!');
  SetConsoleColor($07);

  ExecProc := TExecuteProc(MemoryGetProcAddress(Module, 'Execute'));
  if @ExecProc = nil then
  begin
    SetConsoleColor($0E);
    Writeln('[!] Export "Execute" not found in DLL');
    SetConsoleColor($07);
    MemoryFreeLibrary(Module);
    Exit;
  end;

  Writeln('[*] Calling Execute()...');
  try
    ExecProc;
    SetConsoleColor($0A);
    Writeln('[+] Execute() completed successfully.');
    SetConsoleColor($07);
  except
    on E: Exception do
    begin
      SetConsoleColor($0C);
      Writeln('[!] Exception in Execute(): ', E.Message);
      SetConsoleColor($07);
    end;
  end;

  MemoryFreeLibrary(Module);
  Writeln('[*] DLL unloaded from memory.');
end;

// =============================================================================
// MODE 1: LOCAL FILE PATH
// =============================================================================

procedure ModeLocalFile;
var
  FilePath: string;
  FileStream: TFileStream;
  Data: Pointer;
begin
  Writeln('--- Mode: Local File ---');
  Write('Enter DLL file path: ');
  Readln(FilePath);
  Writeln;

  if not FileExists(FilePath) then
  begin
    SetConsoleColor($0C);
    Writeln('[!] File does not exist: ', FilePath);
    SetConsoleColor($07);
    Exit;
  end;

  try
    FileStream := TFileStream.Create(FilePath, fmOpenRead or fmShareDenyWrite);
    try
      Writeln('[*] Reading ', FileStream.Size, ' bytes from disk...');
      // Allocate memory using standard heap, MemoryLoadLibrary only needs read access
      Data := GetMemory(FileStream.Size);
      if Data = nil then
      begin
        Writeln('[!] Out of memory.');
        Exit;
      end;

      FileStream.ReadBuffer(Data^, FileStream.Size);
      ExecuteFromMemory(Data, FileStream.Size);
    finally
      FreeMemory(Data);
      FileStream.Free;
    end;
  except
    on E: Exception do
    begin
      SetConsoleColor($0C);
      Writeln('[!] Error reading file: ', E.Message);
      SetConsoleColor($07);
    end;
  end;
end;

// =============================================================================
// MODE 2: DIRECT HTTP/HTTPS URL
// =============================================================================

procedure ModeDirectURL;
var
  URL: string;
  hNet, hUrl: HINTERNET;
  BytesRead: DWORD;
  Buffer: array[0..8191] of Byte;
  Stream: TMemoryStream;
begin
  Writeln('--- Mode: Direct URL ---');
  Write('Enter DLL URL (http/https): ');
  Readln(URL);
  Writeln;

  hNet := InternetOpen('MemoryLoaderClient', INTERNET_OPEN_TYPE_PRECONFIG, nil, nil, 0);
  if hNet = nil then
  begin
    Writeln('[!] Failed to initialize WinINet.');
    Exit;
  end;

  hUrl := InternetOpenUrl(hNet, PChar(URL), nil, 0, INTERNET_FLAG_RELOAD, 0);
  if hUrl = nil then
  begin
    Writeln('[!] Failed to open URL. Check the link or your internet connection.');
    InternetCloseHandle(hNet);
    Exit;
  end;

  Stream := TMemoryStream.Create;
  try
    Writeln('[*] Downloading DLL...');
    repeat
      if not InternetReadFile(hUrl, @Buffer[0], SizeOf(Buffer), BytesRead) then
      begin
        Writeln('[!] Error occurred during download.');
        Exit;
      end;

      if BytesRead > 0 then
        Stream.WriteBuffer(Buffer[0], BytesRead);
    until BytesRead = 0;

    Writeln('[*] Download complete. (', Stream.Size, ' bytes)');
    ExecuteFromMemory(Stream.Memory, Stream.Size);
  finally
    Stream.Free;
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hNet);
  end;
end;

// =============================================================================
// MODE 3: TCP SERVER (Original Logic)
// =============================================================================

function RecvBuf(Sock: TSocket; Buf: Pointer; Size: Integer): Integer;
var
  Received, Total: Integer;
  P: PByte;
begin
  Total := 0;
  P := Buf;
  while Total < Size do
  begin
    Received := recv(Sock, P^, Size - Total, 0);
    if Received <= 0 then Exit(Received);
    Inc(Total, Received);
    Inc(P, Received);
  end;
  Result := Total;
end;

procedure ModeTCPServer;
var
  WSAData: TWSAData;
  Sock: TSocket;
  Addr: TSockAddrIn;
  ServerIP: string;
  PortStr: string;
  Port: Integer;
  DllSize: UInt64;
  DllData: PByte;
  Ret: Integer;
begin
  Writeln('--- Mode: TCP Server ---');
  Write('Enter Server IP (e.g., 127.0.0.1): ');
  Readln(ServerIP);
  Write('Enter Server Port: ');
  Readln(PortStr);
  Port := StrToIntDef(PortStr, 0);

  if (Port <= 0) or (Port > 65535) then
  begin
    Writeln('[!] Invalid port number.');
    Exit;
  end;
  Writeln;

  if WSAStartup($0202, WSAData) <> 0 then
  begin
    Writeln('[!] WSAStartup failed');
    Exit;
  end;

  Sock := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if Sock = INVALID_SOCKET then
  begin
    Writeln('[!] socket() failed');
    WSACleanup;
    Exit;
  end;

  Addr.sin_family := AF_INET;
  Addr.sin_addr.S_addr := inet_addr(PAnsiChar(AnsiString(ServerIP)));
  Addr.sin_port := htons(Port);

  Writeln('[*] Connecting to ', ServerIP, ':', Port, '...');
  if connect(Sock, TSockAddr(Addr), SizeOf(Addr)) = SOCKET_ERROR then
  begin
    Writeln('[!] connect() failed');
    closesocket(Sock);
    WSACleanup;
    Exit;
  end;

  Writeln('[+] Connected! Waiting for DLLs (Server sends size as UInt64, then bytes)...');
  Writeln;

  while True do
  begin
    Ret := RecvBuf(Sock, @DllSize, SizeOf(UInt64));
    if Ret <= 0 then
    begin
      Writeln('[*] Server disconnected.');
      Break;
    end;

    if DllSize = 0 then
    begin
      Writeln('[!] Server reported: DLL not found');
      Continue;
    end;

    Writeln('[*] Receiving DLL: ', DllSize, ' bytes...');
    DllData := VirtualAlloc(nil, DllSize, MEM_COMMIT or MEM_RESERVE, PAGE_READWRITE);
    if DllData = nil then
    begin
      Writeln('[!] Failed to allocate memory for DLL');
      Break;
    end;

    Ret := RecvBuf(Sock, DllData, Integer(DllSize));
    if Ret <= 0 then
    begin
      Writeln('[!] Connection lost during transfer');
      VirtualFree(DllData, 0, MEM_RELEASE);
      Break;
    end;

    ExecuteFromMemory(DllData, DllSize);
    VirtualFree(DllData, 0, MEM_RELEASE);
    Writeln;
  end;

  closesocket(Sock);
  WSACleanup;
end;

// =============================================================================
// MAIN MENU
// =============================================================================

var
  Choice: string;

begin
  PrintHeader;
  SetupLoaderLogging;

  while True do
  begin
    Writeln('Select loading method:');
    Writeln('  [1] Local File Path');
    Writeln('  [2] Direct HTTP/HTTPS URL');
    Writeln('  [3] TCP Server (IP/Port)');
    Writeln('  [0] Exit');
    Write('> ');
    Readln(Choice);
    Writeln;

    if Choice = '0' then Break;

    if Choice = '1' then
      ModeLocalFile
    else if Choice = '2' then
      ModeDirectURL
    else if Choice = '3' then
      ModeTCPServer
    else
    begin
      SetConsoleColor($0E);
      Writeln('[!] Invalid choice.');
      SetConsoleColor($07);
    end;

    Writeln;
    Writeln('------------------------------------------------------');
    Writeln;
  end;

  Writeln('Exiting...');
end.
