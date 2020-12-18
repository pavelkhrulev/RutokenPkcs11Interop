using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI40;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI40;

namespace RutokenPkcs11InteropTests.LowLevelAPI40
{
    [TestFixture()]
    public class _LL40_32_ActivationPasswordTest
    {
        [Test()]
        public void _LL40_32_01_ActivationPasswordTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs40);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации администратора
                rv = pkcs11.C_Login(session, CKU.CKU_SO, Settings.SecurityOfficerPinArray,
                    Convert.ToUInt32(Settings.SecurityOfficerPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // TODO: сделать вызов функций активации в правильном порядке
                // и с правильными данными

                // Загрузка ключа активации
                byte[] activationKey = new byte[32];
                rv = pkcs11.C_EX_LoadActivationKey(session, activationKey);
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

                // Установка пароля активации
                rv = pkcs11.C_EX_SetActivationPassword(slotId, password);
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
