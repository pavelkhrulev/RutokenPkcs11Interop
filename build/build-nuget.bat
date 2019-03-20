@setlocal

@rem Delete output directory
rmdir /S /Q nuget
SET Pkcs11InteropDir=..\..\Pkcs11Interop\build

@rem Create output directories
mkdir nuget\lib\net45 || goto :error
mkdir nuget\lib\netstandard2.0 || goto :error
mkdir nuget\lib\monoandroid2.3 || goto :error
mkdir nuget\lib\xamarinios1.0 || goto :error
mkdir nuget\lib\xamarinmac2.0 || goto :error

@rem Copy assemblies to output directories
copy net45\RutokenPkcs11Interop.dll nuget\lib\net45 || goto :error
copy %Pkcs11InteropDir%\net45\Pkcs11Interop.dll nuget\lib\net45 || goto :error
copy netstandard2.0\RutokenPkcs11Interop.dll nuget\lib\netstandard2.0 || goto :error
copy %Pkcs11InteropDir%\netstandard2.0\Pkcs11Interop.dll nuget\lib\netstandard2.0 || goto :error
copy monoandroid2.3\RutokenPkcs11Interop.dll nuget\lib\monoandroid2.3 || goto :error
copy %Pkcs11InteropDir%\monoandroid2.3\Pkcs11Interop.dll nuget\lib\monoandroid2.3 || goto :error
copy xamarinios1.0\RutokenPkcs11Interop.dll nuget\lib\xamarinios1.0 || goto :error
copy %Pkcs11InteropDir%\xamarinios1.0\Pkcs11Interop.dll nuget\lib\xamarinios1.0 || goto :error
copy xamarinmac2.0\RutokenPkcs11Interop.dll nuget\lib\xamarinmac2.0 || goto :error
copy %Pkcs11InteropDir%\xamarinmac2.0\Pkcs11Interop.dll nuget\lib\xamarinmac2.0 || goto :error

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
