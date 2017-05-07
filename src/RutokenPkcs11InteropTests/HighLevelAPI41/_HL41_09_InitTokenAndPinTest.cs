using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI41;
using RutokenPkcs11Interop.HighLevelAPI41;
using RutokenPkcs11Interop.LowLevelAPI41;

namespace RutokenPkcs11InteropTests.HighLevelAPI41
{
    [TestClass]
    public class _HL41_09_InitTokenAndPinTest
    {
        /// <summary>
        /// Basic C_InitToken and C_InitPIN test.
        /// </summary>
        [TestMethod()]
        public void _HL41_09_01_BasicInitTokenAndPinTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

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

        [TestMethod()]
        public void _HL41_09_02_ExtendedInitTokenAndPinTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Формирование параметров для инициализации токена
                var rutokenInitParam = new RutokenInitParam(Settings.SecurityOfficerPin, Settings.NewUserPin,
                    Settings.TokenStdLabel,
                    new List<RutokenFlag> {RutokenFlag.AdminChangeUserPin, RutokenFlag.UserChangeUserPin}, 6, 6,
                    Settings.MAX_ADMIN_RETRY_COUNT, Settings.MAX_USER_RETRY_COUNT, 0);

                // Инициализация токена
                slot.InitTokenExtended(Settings.SecurityOfficerPinArray, rutokenInitParam);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
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
    }
}
