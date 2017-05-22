using System;
using System.Collections.Generic;
using System.IO;

namespace RutokenPkcs11Interop
{
    public static class Settings
    {
        private static string _rutokenEcpDllName = @"rtPKCS11ECP.dll";

        public static string RutokenEcpDllDefaultPath =>
            Path.Combine(Environment.SystemDirectory, _rutokenEcpDllName);

        public static bool OsLockingDefault => true;

        public static uint DefaultLicenseLength => 72;

        public static List<uint> LicenseAllowedNumbers = new List<uint> {1, 2};
    }
}
