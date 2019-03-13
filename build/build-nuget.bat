@setlocal

@rem Delete output directory
rmdir /S /Q nuget

@rem Create output directories
mkdir nuget\lib\net45 || goto :error
@rem mkdir nuget\lib\netstandard1.3 || goto :error
mkdir nuget\lib\netstandard2.0 || goto :error
mkdir nuget\lib\monoandroid2.3 || goto :error
mkdir nuget\lib\xamarinios1.0 || goto :error
mkdir nuget\lib\xamarinmac2.0 || goto :error

@rem Copy assemblies to output directories
copy net45\RutokenPkcs11Interop.dll nuget\lib\net45 || goto :error
@rem copy netstandard1.3\RutokenPkcs11Interop.dll nuget\lib\netstandard1.3 || goto :error
copy netstandard2.0\RutokenPkcs11Interop.dll nuget\lib\netstandard2.0 || goto :error
copy monoandroid2.3\RutokenPkcs11Interop.dll nuget\lib\monoandroid2.3 || goto :error
copy xamarinios1.0\RutokenPkcs11Interop.dll nuget\lib\xamarinios1.0 || goto :error
copy xamarinmac2.0\RutokenPkcs11Interop.dll nuget\lib\xamarinmac2.0 || goto :error

@rem Create package
copy RutokenPkcs11Interop.nuspec nuget || goto :error
nuget pack nuget\RutokenPkcs11Interop.nuspec || goto :error

@echo *** BUILD NUGET SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD NUGET FAILED ***
@endlocal
@exit /b 1
