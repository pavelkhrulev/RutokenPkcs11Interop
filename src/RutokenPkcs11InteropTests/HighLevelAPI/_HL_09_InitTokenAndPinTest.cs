using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestClass]
    public class _HL_09_InitTokenAndPinTest
    {
        /// <summary>
        /// Basic C_InitToken and C_InitPIN test.
        /// </summary>
        [TestMethod()]
        public void _HL_09_01_BasicInitTokenAndPinTest()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Инициализация токена
                slot.InitToken(Settings.SecurityOfficerPin, Settings.TokenStdLabel);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
                {
                    // Аутентификация администратора
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPin);

                    // Инициализация ПИН-кода пользователя
                    session.InitPin(Settings.NormalUserPin);

                    // Завершение сессии
                    session.Logout();
                }
            }
        }
    }
}
