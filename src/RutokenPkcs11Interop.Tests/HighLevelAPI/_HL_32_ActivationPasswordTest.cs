using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_32_ActivationPasswordTest
    {
        [Test()]
        public void _HL_32_01_ActivationPasswordTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
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
