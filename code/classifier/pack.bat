REM @echo off

set VSDIR=%UserProfile%\Documents\Visual Studio 2015\Projects
set exec7z="C:\Program Files\7-Zip\7z.exe"

call :Func "%VSDIR%\caching_policy_classifier"
call :Func "%VSDIR%\fake_dns_server"

REM %exec7z% a -ttar out.tar "%VSDIR%"\*.tar.gz libtins-master.tar.gz install update
REM %exec7z% a -tgzip classifier.tar.gz out.tar
REM del out.tar

move "%VSDIR%"\*.tar.gz .
copy "%VSDIR%"\caching_policy_classifier\caching_policy_classifier\oms.json oms.json
 

goto :EOF

:Func
SET "TARGET=%~1"
del %TARGET%.tar.gz
%exec7z% a -ttar "%TARGET%.tar" "%TARGET%"\*\*.h "%TARGET%"\*\*.hpp "%TARGET%"\*\*.cpp "%TARGET%"\*\Makefile
%exec7z% a -tgzip "%TARGET%.tar.gz" "%TARGET%.tar"
del "%TARGET%.tar"
goto :EOF
