@setlocal

@rem Argument "--with-tests" forces the build of test project
@set arg1=%1

@rem Initialize Visual Studio build environment:
@rem - Visual Studio 2017 Community/Professional/Enterprise is the preferred option
@rem - Visual Studio 2015 is the fallback option (which might or might not work)
@set tools=
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\vsvars32.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@if not defined tools goto :error
call %tools%
@echo on

@rem Delete output directory
rmdir /S /Q xamarinios1.0

@rem Clean solution
msbuild ..\src\RutokenPkcs11Interop.iOS\RutokenPkcs11Interop.iOS.sln ^
	/p:Configuration=Release /p:Platform="Any CPU" /target:Clean || goto :error

@if "%arg1%"=="--with-tests" (
	@rem Build both RutokenPkcs11Interop and RutokenPkcs11Interop.iOS.Tests projects via solution
	msbuild ..\src\RutokenPkcs11Interop.iOS\RutokenPkcs11Interop.iOS.sln ^
		/p:Configuration=Release /p:Platform="Any CPU" /target:Build || goto :error
) else (
	@rem Build only RutokenPkcs11Interop project
	msbuild ..\src\RutokenPkcs11Interop.iOS\RutokenPkcs11Interop\RutokenPkcs11Interop.csproj ^
		/p:Configuration=Release /p:Platform=AnyCPU /target:Build || goto :error
)

@rem Copy result to output directory
mkdir xamarinios1.0 || goto :error
copy ..\src\RutokenPkcs11Interop.iOS\RutokenPkcs11Interop\bin\Release\RutokenPkcs11Interop.dll xamarinios1.0 || goto :error

@echo *** BUILD XAMARINIOS1.0 SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD XAMARINIOS1.0 FAILED ***
@endlocal
@exit /b 1
