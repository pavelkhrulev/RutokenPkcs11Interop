﻿using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI41;
using NUnit.Framework;

namespace RutokenPkcs11InteropTests.HighLevelAPI41
{
    /// <summary>
    /// C_GetInfo tests.
    /// </summary>
    [TestFixture()]
    public class _HL41_02_GetInfoTest
    {
        /// <summary>
        /// Basic C_GetInfo test.
        /// </summary>
        [Test()]
        public void _HL41_02_01_BasicGetInfoTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Do something interesting with library information
                Assert.IsFalse(String.IsNullOrEmpty(libraryInfo.ManufacturerId));
            }
        }
    }
}
