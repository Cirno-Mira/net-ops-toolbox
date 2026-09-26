' NetOps Toolbox - silent launcher (no console window)
' Double-click this file to start the toolbox without any black cmd window.
'
' NOTE: keep this file ASCII-only. cscript on Chinese Windows reads .vbs as
' ANSI/GBK, so non-ASCII bytes here can break string literals.
Option Explicit

Dim fso, sh, here, py, i, cands, q, cmd

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh = CreateObject("WScript.Shell")

here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = here

' Find pythonw.exe (GUI subsystem = no console window).
' Order: conda env "ai" -> miniforge -> whatever is on PATH.
cands = Array( _
    sh.ExpandEnvironmentStrings("%USERPROFILE%") & "\.conda\envs\ai\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%USERPROFILE%") & "\miniconda3\envs\ai\pythonw.exe", _
    sh.ExpandEnvironmentStrings("%USERPROFILE%") & "\anaconda3\envs\ai\pythonw.exe", _
    "C:\ProgramData\miniforge3\envs\ai\pythonw.exe", _
    "C:\ProgramData\miniforge3\pythonw.exe", _
    "pythonw.exe" _
)

py = ""
For i = 0 To UBound(cands)
    If InStr(cands(i), "\") = 0 Then
        py = cands(i)
        Exit For
    ElseIf fso.FileExists(cands(i)) Then
        py = cands(i)
        Exit For
    End If
Next

If py = "" Then
    MsgBox "pythonw.exe not found." & vbCrLf & vbCrLf & _
           "Run 'conda activate ai' first, or edit the candidate paths " & _
           "inside this launcher.", 16, "NetOps Toolbox"
    WScript.Quit 1
End If

q = Chr(34)
cmd = q & py & q & " " & q & fso.BuildPath(here, "main.py") & q

' 0 = hidden window, False = do not wait
sh.Run cmd, 0, False
