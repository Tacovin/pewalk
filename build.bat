@echo off
rem run from a "x64 Native Tools Command Prompt for VS"
if not exist build mkdir build
cl /nologo /O2 /W4 /D_CRT_SECURE_NO_WARNINGS /Fobuild\ /Febuild\pewalk.exe src\*.c
