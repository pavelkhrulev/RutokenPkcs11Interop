@setlocal

@rem Argument "--with-tests" forces the build of test project
@set arg1=%1

@rem Argument "--skip-cleaning" skips solution cleaning
@set arg2=%2

@rem Initialize build environment of Visual Studio 2019 Community/Professional/Enterprise
@set tools=
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
rmdir /S /Q netstandard2.0

@rem Restore dependencies for the solution
msbuild ..\src\RutokenPkcs11Interop.NetStandard\RutokenPkcs11Interop.NetStandard.sln ^
	/p:Configuration=Release /p:Platform="Any CPU" /target:Restore || goto :error

@if not "%arg2%"=="--skip-cleaning" (
	@rem Clean solution
	msbuild ..\src\RutokenPkcs11Interop.NetStandard\RutokenPkcs11Interop.NetStandard.sln ^
		/p:Configuration=Release /p:Platform="Any CPU" /target:Clean || goto :error
)

@rem Build RutokenPkcs11Interop project
nuget restore ..\src\RutokenPkcs11Interop.NetStandard\RutokenPkcs11Interop.NetStandard.sln
msbuild ..\src\RutokenPkcs11Interop.NetStandard\RutokenPkcs11Interop\RutokenPkcs11Interop.csproj ^
	/p:Configuration=Release /p:Platform=AnyCPU /p:TargetFramework=netstandard2.0 ^
	/target:Build || goto :error

@if "%arg1%"=="--with-tests" (
	@rem Build RutokenPkcs11Interop.DotNetCore.Tests project
	msbuild ..\src\RutokenPkcs11Interop.NetStandard\RutokenPkcs11Interop.DotNetCore.Tests\RutokenPkcs11Interop.DotNetCore.Tests.csproj ^
		/p:Configuration=Release /p:Platform=AnyCPU /p:TargetFramework=netcoreapp2.0 ^
		/target:Build || goto :error
)

@rem Copy result to output directory
mkdir netstandard2.0 || goto :error
copy ..\src\RutokenPkcs11Interop.NetStandard\RutokenPkcs11Interop\bin\Release\netstandard2.0\RutokenPkcs11Interop.dll netstandard2.0 || goto :error

@echo *** BUILD netstandard2.0 SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD netstandard2.0 FAILED ***
@endlocal
@exit /b 1
