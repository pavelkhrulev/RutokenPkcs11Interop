using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI41;
using RutokenPkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11InteropTests.HighLevelAPI41
{
    [TestClass]
    public class _HL41_04_TokenInfoTest
    {
        /// <summary>
        /// Basic C_GetTokenInfo test.
        /// </summary>
        [TestMethod()]
        public void _HL41_04_01_TokenInfoTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Get token info
                TokenInfo tokenInfo = slot.GetTokenInfo();

                // Do something interesting with token info
                Assert.IsFalse(String.IsNullOrEmpty(tokenInfo.ManufacturerId));
            }
        }

        /// <summary>
        /// C_EX_GetTokenInfoExtended test.
        /// </summary>
        [TestMethod()]
        public void _HL41_04_02_TokenInfoExtendedTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Get token info
                TokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();

                // Do something interesting with token info
                Assert.IsFalse(String.IsNullOrEmpty(tokenInfo.SerialNumber));
            }
        }
    }
}
