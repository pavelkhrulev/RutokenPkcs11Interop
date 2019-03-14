using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI81;
using NUnit.Framework;

namespace RutokenPkcs11InteropTests.HighLevelAPI81
{
    /// <summary>
    /// C_GetInfo tests.
    /// </summary>
    [TestFixture()]
    public class _HL81_02_GetInfoTest
    {
        /// <summary>
        /// Basic C_GetInfo test.
        /// </summary>
        [Test()]
        public void _HL81_02_01_BasicGetInfoTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 1)
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
