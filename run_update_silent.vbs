Set WshShell = CreateObject("WScript.Shell")
Set FSO = CreateObject("Scripting.FileSystemObject")
ScriptDir = FSO.GetParentFolderName(WScript.ScriptFullName)
WshShell.CurrentDirectory = ScriptDir
WshShell.Run Chr(34) & ScriptDir & "\.venv\Scripts\python.exe" & Chr(34) & " cli.py update", 0, False
