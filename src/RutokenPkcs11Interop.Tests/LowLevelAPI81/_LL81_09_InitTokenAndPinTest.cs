using System;
using System.Runtime.InteropServices;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI81;

namespace RutokenPkcs11InteropTests.LowLevelAPI81
{
    [TestFixture()]
    public class _LL81_09_InitTokenAndPinTest
    {
        /// <summary>
        /// Basic C_InitToken and C_InitPIN test.
        /// </summary>
        [Test()]
        public void _LL81_09_01_BasicInitTokenAndPinTest()
        {
            if (Platform.NativeULongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                // Инициализация токена
                rv = pkcs11.C_InitToken(slotId,
                    Settings.SecurityOfficerPinArray, Convert.ToUInt64(Settings.SecurityOfficerPinArray.Length),
                    ConvertUtils.Utf8StringToBytes(Settings.TokenStdLabel, 32, 0x20));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Открытие RW сессии
                ulong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Аутентификация администратора
                rv = pkcs11.C_Login(session, CKU.CKU_SO, Settings.SecurityOfficerPinArray, Convert.ToUInt64(Settings.SecurityOfficerPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация ПИН-кода пользователя
                rv = pkcs11.C_InitPIN(session, Settings.NormalUserPinArray, Convert.ToUInt64(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии
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

        /// <summary>
        /// Basic C_InitToken and C_InitPIN test.
        /// </summary>
        [Test()]
        public void _LL81_09_02_ExtendedInitTokenAndPinTest()
        {
            if (Platform.NativeULongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                // Инициализация токена
                var rutokenInitParam = new CK_RUTOKEN_INIT_PARAM()
                {
                    SizeofThisStructure = Convert.ToUInt64(Marshal.SizeOf(typeof(CK_RUTOKEN_INIT_PARAM))),
                    UseRepairMode = 0,
                    NewAdminPinLen = Convert.ToUInt64(Settings.SecurityOfficerPinArray.Length),
                    NewUserPinLen = Convert.ToUInt64(Settings.NewUserPinArray.Length),
                    MinAdminPinLen = 6,
                    MinUserPinLen = 6,
                    ChangeUserPINPolicy = Convert.ToUInt64(RutokenFlag.AdminChangeUserPin | RutokenFlag.UserChangeUserPin),
                    MaxAdminRetryCount = Settings.MAX_ADMIN_RETRY_COUNT,
                    MaxUserRetryCount = Settings.MAX_USER_RETRY_COUNT,
                    LabelLen = Convert.ToUInt64(Settings.TokenStdLabelArray.Length),
                    SmMode = 0
                };

                // Выделение памяти для IntPtr (можно не выделять, а использовать GCPinnedArray)
                // После использования нужно освободить память
                rutokenInitParam.NewAdminPin = UnmanagedMemory.Allocate(Settings.SecurityOfficerPinArray.Length);
                UnmanagedMemory.Write(rutokenInitParam.NewAdminPin, Settings.SecurityOfficerPinArray);
                rutokenInitParam.NewUserPin = UnmanagedMemory.Allocate(Settings.NewUserPinArray.Length);
                UnmanagedMemory.Write(rutokenInitParam.NewUserPin, Settings.NewUserPinArray);
                rutokenInitParam.TokenLabel = UnmanagedMemory.Allocate(Settings.TokenStdLabelArray.Length);
                UnmanagedMemory.Write(rutokenInitParam.TokenLabel, Settings.TokenStdLabelArray);

                // Расширенная инициализация токена
                rv = pkcs11.C_EX_InitToken(slotId, Settings.SecurityOfficerPinArray,
                    ref rutokenInitParam);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Освобождение выделенной памяти
                UnmanagedMemory.Free(ref rutokenInitParam.NewAdminPin);
                rutokenInitParam.NewAdminPinLen = 0;
                UnmanagedMemory.Free(ref rutokenInitParam.NewUserPin);
                rutokenInitParam.NewUserPinLen = 0;
                UnmanagedMemory.Free(ref rutokenInitParam.TokenLabel);
                rutokenInitParam.LabelLen = 0;

                // Открытие RW сессии
                ulong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Блокировка PIN-кода пользователя путем ввода неверного пин-кода нужное число раз
                for (var i = 0; i < Settings.MAX_USER_RETRY_COUNT; i++)
                {
                    rv = pkcs11.C_Login(session, CKU.CKU_USER,
                        Settings.WrongUserPinArray, Convert.ToUInt64(Settings.WrongUserPinArray.Length));
                    if (rv != CKR.CKR_PIN_INCORRECT && rv != CKR.CKR_PIN_LOCKED)
                        Assert.Fail(rv.ToString());
                }

                // Аутентификация администратора
                rv = pkcs11.C_Login(session, CKU.CKU_SO,
                    Settings.SecurityOfficerPinArray, Convert.ToUInt64(Settings.SecurityOfficerPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Разблокировка PIN-кода пользователя
                rv = pkcs11.C_EX_UnblockUserPIN(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии администратора
                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Аутентификация пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER,
                    Settings.NewUserPinArray, Convert.ToUInt64(Settings.NewUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Изменение метки токена на "длинную"
                rv = pkcs11.C_EX_SetTokenName(session, Settings.TokenLongLabelArray);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Получение метки токена
                ulong tokenLabelLength = 0;
                rv = pkcs11.C_EX_GetTokenName(session, null, ref tokenLabelLength);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(tokenLabelLength > 0);

                byte[] tokenLabel = new byte[tokenLabelLength];

                rv = pkcs11.C_EX_GetTokenName(session, tokenLabel, ref tokenLabelLength);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Сравнение записанной и полученной метки
                Assert.IsTrue(Convert.ToBase64String(Settings.TokenLongLabelArray) == Convert.ToBase64String(tokenLabel));

                // Установка PIN-кода пользователя по-умолчанию
                rv = pkcs11.C_SetPIN(session, Settings.NormalUserPinArray,
                    Convert.ToUInt64(Settings.NormalUserPinArray.Length),
                    Settings.NormalUserPinArray,
                    Convert.ToUInt64(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// Тест для проверки работы с локальными ПИН-кодами
        /// </summary>
        [Test()]
        public void _LL81_09_03_LocalPinTest()
        {
            if (Platform.NativeULongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                // Создание локального PIN-кода токена с ID = 0x03
                rv = pkcs11.C_EX_SetLocalPIN(slotId, Settings.NormalUserPinArray,
                    Settings.LocalPinArray, Settings.LocalPinId1);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Создание локального PIN-кода токена с ID = 0x1E
                rv = pkcs11.C_EX_SetLocalPIN(slotId, Settings.NormalUserPinArray,
                    Settings.LocalPinArray, Settings.LocalPinId2);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии работы с библиотекой
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
