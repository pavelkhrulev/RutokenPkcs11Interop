using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using RutokenPkcs11Interop.LowLevelAPI81;

namespace RutokenPkcs11InteropTests.LowLevelAPI81
{
    [TestFixture()]
    public class _LL81_31_LicenseTest
    {
        [Test()]
        public void _LL81_31_01_SetAndGetLicenseTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                ulong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации администратора
                rv = pkcs11.C_Login(session, CKU.CKU_SO, Settings.SecurityOfficerPinArray, Convert.ToUInt64(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Сохранение лицензии
                ulong licenseNum = 1;
                byte[] setlicense = new byte[RutokenPkcs11Interop.Settings.DefaultLicenseLength];
                (new Random()).NextBytes(setlicense);
                rv = pkcs11.C_EX_SetLicense(session, licenseNum, setlicense);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Чтение длины лицензии
                ulong licenseLen = 0;
                rv = pkcs11.C_EX_GetLicense(session, licenseNum, null, ref licenseLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(licenseLen > 0);
                Assert.AreEqual(Convert.ToUInt64(setlicense.Length), licenseLen);

                // Чтение лицензии
                byte[] getLicense = new byte[licenseLen];
                rv = pkcs11.C_EX_GetLicense(session, licenseNum, getLicense, ref licenseLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверка на совпадение записанной и прочитанной лицензии
                Assert.IsTrue(Convert.ToBase64String(setlicense) == Convert.ToBase64String(getLicense));

                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
