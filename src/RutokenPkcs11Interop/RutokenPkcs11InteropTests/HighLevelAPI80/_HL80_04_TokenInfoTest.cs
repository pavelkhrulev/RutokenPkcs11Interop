using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI80;
using RutokenPkcs11Interop.HighLevelAPI80;

namespace RutokenPkcs11InteropTests.HighLevelAPI80
{
    [TestFixture()]
    public class _HL80_04_TokenInfoTest
    {
        /// <summary>
        /// Basic C_GetTokenInfo test.
        /// </summary>
        [Test()]
        public void _HL80_04_01_TokenInfoTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
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
        [Test()]
        public void _HL80_04_02_TokenInfoExtendedTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
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
