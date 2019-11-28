rem положить в корневой каталог, т.е. где файл *.SLN

del /s /ah /f *.suo
del /s /f *.user
del /s /f *.cache
del /s /f *.scc
del /s /f *.vssscc
del /s /f *.vspscc
del /s /ah StyleCop.Cache
rd /s /q bin obj TestResults

del /s /f *.ipch
del /s /f *.lastbuildstate
del /s /f *.log
del /s /f *.obj
del /s /f *.pdb
del /s /f *.tlog
del /s /f *.sdf
REM del /s /f *.filters

RMDIR /s /q ipch
RMDIR /s /q Debug
RMDIR /s /q x64\Debug
RMDIR /s /q Hooker\Debug
RMDIR /s /q Hooker\x64
RMDIR /s /q HookerWatcher\Debug

del /s /f *.manifest
del /s /f *.exp

del /s /f *.pch
del /s /f *.res
del /s /f *.aps

pause

