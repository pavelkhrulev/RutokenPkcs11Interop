using System;
using System.IO;

namespace RutokenPkcs11Interop
{
    public static class Settings
    {
        private static string _rutokenEcpDllName = @"rtPKCS11ECP.dll";

        public static string RutokenEcpDllDefaultPath =>
            Path.Combine(Environment.SystemDirectory, _rutokenEcpDllName);

        public static bool OsLockingDefault => true;
    }
}
