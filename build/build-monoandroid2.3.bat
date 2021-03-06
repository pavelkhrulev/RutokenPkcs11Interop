@setlocal

@rem Argument "--with-tests" forces the build of test project
@set arg1=%1

@rem Initialize Visual Studio build environment:
@rem - Visual Studio 2019 Community/Professional/Enterprise is the preferred option
@set tools=
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\vsvars32.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2019\Enterprise\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@if not defined tools goto :error
call %tools%
@echo on

@rem Delete output directory
rmdir /S /Q monoandroid2.3

@rem Clean solution
msbuild ..\src\RutokenPkcs11Interop.Android\RutokenPkcs11Interop.Android.sln ^
	/p:Configuration=Release /p:Platform="Any CPU" /target:Clean || goto :error

nuget restore ..\src\RutokenPkcs11Interop.Android\RutokenPkcs11Interop.Android.sln
@if "%arg1%"=="--with-tests" (
	@rem Build both RutokenRutokenPkcs11Interop and RutokenRutokenPkcs11Interop.Android.Tests projects via solution
	msbuild ..\src\RutokenPkcs11Interop.Android\RutokenPkcs11Interop.Android.sln ^
		/p:Configuration=Release /p:Platform="Any CPU" /target:Build || goto :error
) else (
	@rem Build only RutokenPkcs11Interop project
	msbuild ..\src\RutokenPkcs11Interop.Android\RutokenPkcs11Interop\RutokenPkcs11Interop.csproj ^
		/p:Configuration=Release /p:Platform=AnyCPU /target:Build || goto :error
)

@rem Copy result to output directory
mkdir monoandroid2.3 || goto :error
copy ..\src\RutokenPkcs11Interop.Android\RutokenPkcs11Interop\bin\Release\RutokenPkcs11Interop.dll monoandroid2.3 || goto :error

@echo *** BUILD MONOANDROID2.3 SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD MONOANDROID2.3 FAILED ***
@endlocal
@exit /b 1
