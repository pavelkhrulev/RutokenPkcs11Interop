@setlocal

@rem Delete output directory
rmdir /S /Q nuget

@rem Create output directories
mkdir nuget\lib\net45 || goto :error
mkdir nuget\lib\netstandard2.0 || goto :error
mkdir nuget\lib\monoandroid2.3 || goto :error
mkdir nuget\lib\xamarinios1.0 || goto :error
mkdir nuget\lib\xamarinmac2.0 || goto :error

@rem Copy assemblies to output directories
copy net45\RutokenPkcs11Interop.dll nuget\lib\net45 || goto :error
copy netstandard2.0\RutokenPkcs11Interop.dll nuget\lib\netstandard2.0 || goto :error
copy monoandroid2.3\RutokenPkcs11Interop.dll nuget\lib\monoandroid2.3 || goto :error
copy xamarinios1.0\RutokenPkcs11Interop.dll nuget\lib\xamarinios1.0 || goto :error
copy xamarinmac2.0\RutokenPkcs11Interop.dll nuget\lib\xamarinmac2.0 || goto :error

@rem prepare spec file
set dllfile= nuget\lib\net45\RutokenPkcs11Interop.dll
powershell -NoLogo -NoProfile -Command (Get-Item %dllfile%).VersionInfo.FileVersion > tmpFile || goto :error
set /p version= < tmpFile
powershell -NoLogo -NoProfile -Command (Get-Item %dllfile%).VersionInfo.LegalCopyright > tmpFile || goto :error
set /p copyright= < tmpFile

del tmpFile

set tmplfile=RutokenPkcs11Interop.nuspec.tmpl
set nuspecfile=RutokenPkcs11Interop.nuspec
powershell -Command "(Get-Content %tmplfile%).replace('VERSION', '%version%').replace('COPYRIGHT', '%copyright%') | Set-Content %nuspecfile%" || goto :error

@rem Create package
move %nuspecfile% nuget || goto :error
nuget pack nuget\%nuspecfile% || goto :error

@echo *** BUILD NUGET SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD NUGET FAILED ***
@endlocal
@exit /b 1
