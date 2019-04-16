using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    /// <summary>
    /// C_GetInfo tests.
    /// </summary>
    [TestFixture()]
    public class _HL_02_GetInfoTest
    {
        /// <summary>
        /// Basic C_GetInfo test.
        /// </summary>
        [Test()]
        public void _HL_02_01_BasicGetInfoTest()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                LibraryInfo libraryInfo = pkcs11.GetInfo();

                // Do something interesting with library information
                Assert.IsFalse(String.IsNullOrEmpty(libraryInfo.ManufacturerId));
            }
        }
    }
}
