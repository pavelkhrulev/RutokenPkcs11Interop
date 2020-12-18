using System;
using System.Runtime.InteropServices;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI40;
using Net.RutokenPkcs11Interop.LowLevelAPI40;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI40
{
    [TestFixture()]
    public class _LL40_04_TokenInfoTest
    {
        /// <summary>
        /// Basic C_GetTokenInfo test.
        /// </summary>
        [Test()]
        public void _LL40_04_01_TokenInfoTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs40);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                // Получение информации о токене
                var tokenInfo = new CK_TOKEN_INFO();
                rv = pkcs11.C_GetTokenInfo(slotId, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsFalse(String.IsNullOrEmpty(ConvertUtils.BytesToUtf8String(tokenInfo.ManufacturerId)));

                // Завершение сессии
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_EX_GetTokenInfoExtended test.
        /// </summary>
        [Test()]
        public void _LL40_04_02_TokenInfoExtendedTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs40);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                // Получение расширенной информации о токене
                var tokenInfo = new CK_TOKEN_INFO_EXTENDED
                {
                    SizeofThisStructure = Convert.ToUInt32(Marshal.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)))
                };

                rv = pkcs11.C_EX_GetTokenInfoExtended(slotId, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsFalse(String.IsNullOrEmpty(ConvertUtils.BytesToUtf8String(tokenInfo.ATR)));

                // Завершение сессии
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
