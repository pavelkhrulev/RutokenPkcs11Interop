using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI81;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI81;

namespace RutokenPkcs11InteropTests.HighLevelAPI81
{
    [TestClass]
    public class _HL81_32_ActivationPasswordTest
    {
        [TestMethod]
        public void _HL81_32_01_ActivationPasswordTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 1)
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
