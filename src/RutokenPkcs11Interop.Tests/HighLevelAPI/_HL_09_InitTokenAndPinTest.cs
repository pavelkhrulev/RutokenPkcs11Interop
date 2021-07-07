using System.Collections.Generic;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_09_InitTokenAndPinTest
    {
        /// <summary>
        /// Basic C_InitToken and C_InitPIN test.
        /// </summary>
        [Test()]
        public void _HL_09_01_BasicInitTokenAndPinTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Инициализация токена
                slot.InitToken(Settings.SecurityOfficerPin, Settings.TokenStdLabel);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
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

        [Test()]
        public void _HL_09_02_ExtendedInitTokenAndPinTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = (IRutokenSlot) Helpers.GetUsableSlot(pkcs11);

                // Формирование параметров для инициализации токена
                var rutokenInitParam = Settings.Factories.RutokenInitParamFactory.Create(Settings.SecurityOfficerPin, Settings.NewUserPin,
                    Settings.TokenStdLabel,
                    new List<RutokenFlag> { RutokenFlag.AdminChangeUserPin, RutokenFlag.UserChangeUserPin }, 6, 6,
                    Settings.MAX_ADMIN_RETRY_COUNT, Settings.MAX_USER_RETRY_COUNT, 0);

                // Инициализация токена
                slot.InitTokenExtended(Settings.SecurityOfficerPin, rutokenInitParam);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    // Блокировка PIN-кода пользователя путем ввода неверного пин-кода нужное число раз
                    try
                    {
                        session.Login(CKU.CKU_USER, Settings.WrongUserPinArray);
                    }
                    catch (Pkcs11Exception ex)
                    {
                        if (ex.RV != CKR.CKR_PIN_INCORRECT && ex.RV != CKR.CKR_PIN_LOCKED)
                            throw;
                    }

                    // Аутентификация администратора
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPinArray);

                    // Разблокировка PIN-кода пользователя
                    session.UnblockUserPIN();

                    // Завершение сессии администратора
                    session.Logout();

                    // Аутентификация пользователя
                    session.Login(CKU.CKU_USER, Settings.NewUserPinArray);

                    // Изменение метки токена на "длинную"
                    session.SetTokenName(Settings.TokenLongLabel);

                    // Получение метки токена
                    string tokenLabel = session.GetTokenLabel();

                    // Сравнение записанной и полученной метки
                    Assert.IsTrue(Settings.TokenLongLabel == tokenLabel);

                    // Установка PIN-кода пользователя по-умолчанию
                    session.SetPin(Settings.NormalUserPinArray, Settings.NormalUserPinArray);
                }
            }
        }

        [Test()]
        public void _HL_09_03_ExtendedInitTokenRepairModeTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = (IRutokenSlot) Helpers.GetUsableSlot(pkcs11);

                // Формирование параметров для инициализации токена
                var rutokenInitParam = Settings.Factories.RutokenInitParamFactory.Create(Settings.SecurityOfficerPin, Settings.NewUserPin,
                    Settings.TokenStdLabel,
                    new List<RutokenFlag> { RutokenFlag.AdminChangeUserPin, RutokenFlag.UserChangeUserPin }, 6, 6,
                    Settings.MAX_ADMIN_RETRY_COUNT, Settings.MAX_USER_RETRY_COUNT, 0, true);

                // Инициализация токена
                slot.InitTokenExtended(Settings.SecurityOfficerPin, rutokenInitParam);
            }
        }
    }
}
