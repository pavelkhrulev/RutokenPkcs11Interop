using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI41;

namespace RutokenPkcs11InteropTests.LowLevelAPI41
{
    [TestClass]
    public class _LL41_32_Activation
    {
        [TestMethod]
        public void _LL41_32_01_ActivationPasswordTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_SO, Settings.SecurityOfficerPinArray,
                    Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Получение длины пароля активации
                uint passwordLength = 0;

                rv = pkcs11.C_EX_GenerateActivationPassword(session, (uint)ActivationPasswordNumber.GenerateNextPassword,
                    null, ref passwordLength, (uint)ActivationPasswordCharacterSet.CapsAndDigits);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(passwordLength > 0);

                // Генерация пароля активации
                byte[] password = new byte[passwordLength];
                rv = pkcs11.C_EX_GenerateActivationPassword(session, (uint)ActivationPasswordNumber.GenerateNextPassword,
                    password, ref passwordLength, (uint)ActivationPasswordCharacterSet.CapsAndDigits);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

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
