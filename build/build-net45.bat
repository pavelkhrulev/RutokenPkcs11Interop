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
rmdir /S /Q net45

@rem Clean solution
msbuild ..\src\RutokenPkcs11Interop\RutokenPkcs11Interop.sln ^
	/p:Configuration=Release /p:Platform="Any CPU" /p:TargetFrameworkVersion=v4.5 ^
	/target:Clean || goto :error

@rem Build RutokenPkcs11Interop project
nuget restore ..\src\RutokenPkcs11Interop\RutokenPkcs11Interop.sln
msbuild ..\src\RutokenPkcs11Interop\RutokenPkcs11Interop\RutokenPkcs11Interop.csproj ^
	/p:Configuration=Release /p:Platform=AnyCPU /p:TargetFrameworkVersion=v4.5 ^
	/target:Build || goto :error

@if "%arg1%"=="--with-tests" (
	@rem Build RutokenPkcs11InteropTests project
	msbuild ..\src\RutokenPkcs11Interop\RutokenPkcs11InteropTests\RutokenPkcs11InteropTests.csproj ^
		/p:Configuration=Release /p:Platform=AnyCPU /p:TargetFrameworkVersion=v4.5 ^
		/target:Build || goto :error
)

@rem Copy result to output directory
mkdir net45 || goto :error
copy ..\src\RutokenPkcs11Interop\RutokenPkcs11Interop\bin\Release\RutokenPkcs11Interop.dll net45 || goto :error

@echo *** BUILD NET45 SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD NET45 FAILED ***
@endlocal
@exit /b 1
