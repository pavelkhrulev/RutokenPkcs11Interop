﻿using System.Collections.Generic;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI40;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI40;

namespace RutokenPkcs11InteropTests.HighLevelAPI40
{
    [TestFixture()]
    public class _HL40_09_InitTokenAndPinTest
    {
        /// <summary>
        /// Basic C_InitToken and C_InitPIN test.
        /// </summary>
        [Test()]
        public void _HL40_09_01_BasicInitTokenAndPinTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Инициализация токена
                slot.InitToken(Settings.SecurityOfficerPin, Settings.TokenStdLabel);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
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
        public void _HL40_09_02_ExtendedInitTokenAndPinTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Формирование параметров для инициализации токена
                var rutokenInitParam = new RutokenInitParam(Settings.SecurityOfficerPin, Settings.NewUserPin,
                    Settings.TokenStdLabel,
                    new List<RutokenFlag> {RutokenFlag.AdminChangeUserPin, RutokenFlag.UserChangeUserPin}, 6, 6,
                    Settings.MAX_ADMIN_RETRY_COUNT, Settings.MAX_USER_RETRY_COUNT, 0);

                // Инициализация токена
                slot.InitTokenExtended(Settings.SecurityOfficerPin, rutokenInitParam);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
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
        public void _HL40_09_03_ExtendedInitTokenRepairModeTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Формирование параметров для инициализации токена
                var rutokenInitParam = new RutokenInitParam(Settings.SecurityOfficerPin, Settings.NewUserPin,
                    Settings.TokenStdLabel,
                    new List<RutokenFlag> { RutokenFlag.AdminChangeUserPin, RutokenFlag.UserChangeUserPin }, 6, 6,
                    Settings.MAX_ADMIN_RETRY_COUNT, Settings.MAX_USER_RETRY_COUNT, 0, true);

                // Инициализация токена
                slot.InitTokenExtended(Settings.SecurityOfficerPin, rutokenInitParam);
            }
        }
    }
}
