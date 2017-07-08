using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestClass]
    public class _HL_32_ActivationPasswordTest
    {
        [TestMethod]
        public void _HL_32_01_ActivationPasswordTest()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
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
