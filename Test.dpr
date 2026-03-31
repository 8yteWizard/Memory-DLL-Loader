library Test;

uses
  Winapi.Windows,
  Winapi.ShellAPI;

procedure Execute; stdcall;
begin
  ShellExecute(0, nil, 'notepad.exe', nil, nil, SW_SHOWNORMAL);
end;

exports
  Execute;

begin
end.
