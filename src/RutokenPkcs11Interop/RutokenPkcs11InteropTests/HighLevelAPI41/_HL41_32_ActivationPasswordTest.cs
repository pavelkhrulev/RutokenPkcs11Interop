﻿using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI41;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11InteropTests.HighLevelAPI41
{
    [TestFixture()]
    public class _HL41_32_ActivationPasswordTest
    {
        [Test()]
        public void _HL41_32_01_ActivationPasswordTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации администратора
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPin);

                    // TODO: сделать вызов функций активации в правильном порядке
                    // и с правильными данными

                    // Загрузка ключа активации
                    byte[] activationKey = new byte[32];
                    session.LoadActivationKey(activationKey);

                    // Получение пароля активации
                    byte[] activationPassword = session.GenerateActivationPassword(
                        ActivationPasswordNumber.GenerateNextPassword, ActivationPasswordCharacterSet.CapsAndDigits);

                    // Установка пароля активации
                    slot.SetActivationPassword(activationPassword);

                    session.Logout();
                }
            }
        }
    }
}
