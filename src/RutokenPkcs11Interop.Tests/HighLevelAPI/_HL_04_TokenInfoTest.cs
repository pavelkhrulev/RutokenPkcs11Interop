using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_04_TokenInfoTest
    {
        /// <summary>
        /// Basic C_GetTokenInfo test.
        /// </summary>
        [Test()]
        public void _HL_04_01_TokenInfoTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Get token info
                ITokenInfo tokenInfo = slot.GetTokenInfo();

                // Do something interesting with token info
                Assert.IsFalse(String.IsNullOrEmpty(tokenInfo.ManufacturerId));
            }
        }

        /// <summary>
        /// C_EX_GetTokenInfoExtended test.
        /// </summary>
        [Test()]
        public void _HL_04_02_TokenInfoExtendedTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Get token info
                ITokenInfoExtended tokenInfo = slot.GetTokenInfoExtended();

                // Do something interesting with token info
                Assert.IsFalse(String.IsNullOrEmpty(tokenInfo.SerialNumber));
            }
        }
    }
}
