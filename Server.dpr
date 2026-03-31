program Server;

{$APPTYPE CONSOLE}
{$ALIGN 8}

uses
  System.SysUtils,
  System.IOUtils,
  System.Math,
  Winapi.Winsock2;

const
  PORT = 4444;

function SendBuf(Sock: TSocket; Buf: Pointer; Size: Integer): Integer;
begin
  Result := send(Sock, Buf^, Size, 0);
end;

var
  WSAData: TWSAData;
  ServerSock, ClientSock: TSocket;
  Addr: TSockAddrIn;
  DllPath, Cmd: string;
  DllBytes: TBytes;
  SizeToSend: UInt64;
  TotalSent, Sent: Integer;

begin
  try
    if WSAStartup($0202, WSAData) <> 0 then // <-- Fixes MakeWord()
    begin
      Exit;
    end;

    ServerSock := socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if ServerSock = INVALID_SOCKET then
    begin
      WSACleanup;
      Exit;
    end;

    Addr.sin_family := AF_INET;
    Addr.sin_addr.S_addr := INADDR_ANY;
    Addr.sin_port := htons(PORT);

    if bind(ServerSock, TSockAddr(Addr), SizeOf(Addr)) = SOCKET_ERROR then
    begin
      closesocket(ServerSock);
      WSACleanup;
      Exit;
    end;

    if listen(ServerSock, 1) = SOCKET_ERROR then
    begin
      closesocket(ServerSock);
      WSACleanup;
      Exit;
    end;

    Writeln('=== TCP DLL Server ===');
    Writeln('Listening on port ', PORT);
    Writeln('Waiting for client connection...');
    Writeln;

    ClientSock := accept(ServerSock, nil, nil);
    if ClientSock = INVALID_SOCKET then
    begin
      Writeln('accept() failed: ', WSAGetLastError);
      closesocket(ServerSock);
      WSACleanup;
      Exit;
    end;

    Writeln('Client connected!');
    Writeln;

    while True do
    begin
      Write('Enter plugin name (without extension .dll, or "exit"): ');
      Readln(Cmd);
      Cmd := Trim(Cmd);

      if SameText(Cmd, 'exit') then
        Break;

      DllPath := TPath.Combine(
        TPath.Combine(ExtractFilePath(ParamStr(0)), 'Plugins'),
        Cmd + '.dll');

      if not TFile.Exists(DllPath) then
      begin
        Writeln('  [!] DLL not found: ', DllPath);
        SizeToSend := 0;
        SendBuf(ClientSock, @SizeToSend, SizeOf(UInt64));
        Continue;
      end;

      DllBytes := TFile.ReadAllBytes(DllPath);
      SizeToSend := Length(DllBytes);

      Writeln('  [*] Found: ', DllPath);
      Writeln('  [*] Size: ', SizeToSend, ' bytes');
      Write('  [*] Sending...');

      if SendBuf(ClientSock, @SizeToSend, SizeOf(UInt64)) = SOCKET_ERROR then
      begin
        Writeln(' FAILED (send size)');
        Break;
      end;

      TotalSent := 0;
      while TotalSent < Length(DllBytes) do
      begin
        Sent := SendBuf(ClientSock,
          @DllBytes[TotalSent],
          Min(8192, Length(DllBytes) - TotalSent));
        if Sent <= 0 then
        begin
          Writeln(' FAILED (send data)');
          Break;
        end;
        Inc(TotalSent, Sent);
      end;

      if TotalSent = Length(DllBytes) then
        Writeln(' OK')
      else
        Break;
    end;

    closesocket(ClientSock);
    closesocket(ServerSock);
    WSACleanup;
    Writeln;
    Writeln('Server stopped.');
  except
    on E: Exception do
    begin
      Writeln('Error: ', E.Message);
      WSACleanup;
    end;
  end;
end.
