﻿using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI40;
using Net.Pkcs11Interop.LowLevelAPI40.MechanismParams;
using NUnit.Framework;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI40;
using Net.RutokenPkcs11Interop.LowLevelAPI40.MechanismParams;

using NativeULong = System.UInt32;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI40
{
    [TestFixture()]
    public class _LL_25_26_DeriveAndWrapKeyTest
    {
        [Test()]
        public void _LL_25_26_01_DeriveAndWrap_VKO_Gost3410_01_Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs40);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                // для выработки общего ключа
                byte[] ukm = new byte[Settings.UKM_LENGTH];
                rv = pkcs11.C_GenerateRandom(session, ukm, Convert.ToUInt32(ukm.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация значения сессионного ключа
                byte[] sessionKeyValue = new byte[Settings.GOST_28147_KEY_SIZE];
                rv = pkcs11.C_GenerateRandom(session, sessionKeyValue, Convert.ToUInt32(sessionKeyValue.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2001 отправителя
                NativeULong senderPubKeyId = CK.CK_INVALID_HANDLE;
                NativeULong senderPrivKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGostKeyPair(pkcs11, session, ref senderPubKeyId, ref senderPrivKeyId, Settings.GostKeyPairId1);

                // Генерация ключевой пары ГОСТ Р 34.10-2001 получателя
                NativeULong recipientPubKeyId = CK.CK_INVALID_HANDLE;
                NativeULong recipientPrivKeyId = CK.CK_INVALID_HANDLE;
                 Helpers.GenerateGostKeyPair(pkcs11, session, ref recipientPubKeyId, ref recipientPrivKeyId, Settings.GostKeyPairId2);

                // Выработка общего ключа на стороне отправителя
                NativeULong senderDerivedKeyId = CK.CK_INVALID_HANDLE;
                Helpers.Derive_GostR3410_Key(pkcs11, session, recipientPubKeyId, senderPrivKeyId, ukm, ref senderDerivedKeyId);

                // Шаблон для создания маскируемого ключа
                CK_ATTRIBUTE[] sessionKeyTemplate = new CK_ATTRIBUTE[9];
                sessionKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                sessionKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.WrappedGost28147_89KeyLabel);
                sessionKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
                sessionKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
                sessionKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
                sessionKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
                sessionKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_VALUE, sessionKeyValue);
                sessionKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
                sessionKeyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

                // Выработка ключа, который будет замаскирован
                NativeULong sessionKeyId = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_CreateObject(session, sessionKeyTemplate, Convert.ToUInt32(sessionKeyTemplate.Length), ref sessionKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(sessionKeyId != CK.CK_INVALID_HANDLE);

                // Определение параметров механизма маскирования
                // В LowLevelAPI выделенная для параметров память должны быть освобождена после использования
                var wrapMechanismParams = new CK_KEY_DERIVATION_STRING_DATA
                {
                    Data = UnmanagedMemory.Allocate(ukm.Length),
                    Len = Convert.ToUInt32(ukm.Length)
                };
                UnmanagedMemory.Write(wrapMechanismParams.Data, ukm);
                CK_MECHANISM wrapMechanism = CkmUtils.CreateMechanism((NativeULong)CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                // Получение длины маскированного ключа
                NativeULong wrappedKeyLen = 0;
                rv = pkcs11.C_WrapKey(session, ref wrapMechanism, senderDerivedKeyId, sessionKeyId, null, ref wrappedKeyLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(wrappedKeyLen > 0);

                byte[] wrappedKey = new byte[wrappedKeyLen];

                // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                rv = pkcs11.C_WrapKey(session, ref wrapMechanism, senderDerivedKeyId, sessionKeyId, wrappedKey, ref wrappedKeyLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выработка общего ключа на стороне получателя
                NativeULong recipientDerivedKeyId = CK.CK_INVALID_HANDLE;
                Helpers.Derive_GostR3410_Key(pkcs11, session, senderPubKeyId, recipientPrivKeyId, ukm, ref recipientDerivedKeyId);

                // Шаблон демаскированного ключа
                CK_ATTRIBUTE[] unwrappedKeyTemplate = new CK_ATTRIBUTE[8];
                unwrappedKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                unwrappedKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.UnwrappedGost28147_89KeyLabel);
                unwrappedKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
                unwrappedKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
                unwrappedKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
                unwrappedKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
                unwrappedKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
                unwrappedKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

                // Демаскирование сессионного ключа с помощью общего выработанного
                // ключа на стороне получателя
                NativeULong unwrappedKeyId = 0;
                rv = pkcs11.C_UnwrapKey(session, ref wrapMechanism, recipientDerivedKeyId, wrappedKey, wrappedKeyLen,
                    unwrappedKeyTemplate, Convert.ToUInt32(unwrappedKeyTemplate.Length), ref unwrappedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                CK_ATTRIBUTE[] valueTemplate = new CK_ATTRIBUTE[1];
                valueTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_VALUE);
                valueTemplate[0].value = UnmanagedMemory.Allocate(Convert.ToInt32(32));
                valueTemplate[0].valueLen = 32;

                rv = pkcs11.C_GetAttributeValue(session, unwrappedKeyId, valueTemplate, Convert.ToUInt32(valueTemplate.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Сравнение ключа
                byte[] unwrappedKey = UnmanagedMemory.Read(valueTemplate[0].value, Convert.ToInt32(valueTemplate[0].valueLen));
                Assert.IsTrue(Convert.ToBase64String(sessionKeyValue) == Convert.ToBase64String(unwrappedKey));

                // Освобождение выделенной памяти для параметров механизма
                UnmanagedMemory.Free(ref wrapMechanismParams.Data);
                wrapMechanismParams.Len = 0;
                UnmanagedMemory.Free(ref wrapMechanism.Parameter);
                wrapMechanism.ParameterLen = 0;

                // Освобождение выделенной памяти под аттрибуты
                for (int i = 0; i < valueTemplate.Length; i++)
                {
                    UnmanagedMemory.Free(ref valueTemplate[i].value);
                    valueTemplate[i].valueLen = 0;
                }

                for (int i = 0; i < sessionKeyTemplate.Length; i++)
                {
                    UnmanagedMemory.Free(ref sessionKeyTemplate[i].value);
                    sessionKeyTemplate[i].valueLen = 0;
                }

                for (int i = 0; i < unwrappedKeyTemplate.Length; i++)
                {
                    UnmanagedMemory.Free(ref unwrappedKeyTemplate[i].value);
                    unwrappedKeyTemplate[i].valueLen = 0;
                }

                // Удаляем созданные пары ключей
                rv = pkcs11.C_DestroyObject(session, senderPrivKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, senderPubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientPrivKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientPubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Удаляем сессионный ключ
                rv = pkcs11.C_DestroyObject(session, sessionKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Удаляем наследованные ключи
                rv = pkcs11.C_DestroyObject(session, senderDerivedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientDerivedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Закрываем сессию
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

        [Test()]
        public void _LL_25_26_02_DeriveAndWrap_VKO_Gost3410_12_Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs40);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                // для выработки общего ключа
                byte[] ukm = new byte[Settings.UKM_LENGTH];
                rv = pkcs11.C_GenerateRandom(session, ukm, Convert.ToUInt32(ukm.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация значения сессионного ключа
                byte[] sessionKeyValue = new byte[Settings.GOST_28147_KEY_SIZE];
                rv = pkcs11.C_GenerateRandom(session, sessionKeyValue, Convert.ToUInt32(sessionKeyValue.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2012 отправителя
                NativeULong senderPubKeyId = CK.CK_INVALID_HANDLE;
                NativeULong senderPrivKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGost512KeyPair(pkcs11, session, ref senderPubKeyId, ref senderPrivKeyId, Settings.Gost512KeyPairId1);

                // Генерация ключевой пары ГОСТ Р 34.10-2012 получателя
                NativeULong recipientPubKeyId = CK.CK_INVALID_HANDLE;
                NativeULong recipientPrivKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGost512KeyPair(pkcs11, session, ref recipientPubKeyId, ref recipientPrivKeyId, Settings.Gost512KeyPairId2);

                // Выработка общего ключа на стороне отправителя
                NativeULong senderDerivedKeyId = CK.CK_INVALID_HANDLE;
                Helpers.Derive_GostR3410_12_Key(pkcs11, session, recipientPubKeyId, senderPrivKeyId, ukm, ref senderDerivedKeyId);

                // Шаблон для создания маскируемого ключа
                CK_ATTRIBUTE[] sessionKeyTemplate = new CK_ATTRIBUTE[9];
                sessionKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                sessionKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.WrappedGost28147_89KeyLabel);
                sessionKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
                sessionKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
                sessionKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
                sessionKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
                sessionKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_VALUE, sessionKeyValue);
                sessionKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
                sessionKeyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

                // Выработка ключа, который будет замаскирован
                NativeULong sessionKeyId = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_CreateObject(session, sessionKeyTemplate, Convert.ToUInt32(sessionKeyTemplate.Length), ref sessionKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(sessionKeyId != CK.CK_INVALID_HANDLE);

                // Определение параметров механизма маскирования
                // В LowLevelAPI выделенная для параметров память должны быть освобождена после использования
                CK_KEY_DERIVATION_STRING_DATA wrapMechanismParams = new CK_KEY_DERIVATION_STRING_DATA();
                wrapMechanismParams.Data = UnmanagedMemory.Allocate(ukm.Length);
                UnmanagedMemory.Write(wrapMechanismParams.Data, ukm);
                wrapMechanismParams.Len = Convert.ToUInt32(ukm.Length);
                CK_MECHANISM wrapMechanism = CkmUtils.CreateMechanism(CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                // Получение длины маскированного ключа
                NativeULong wrappedKeyLen = 0;
                rv = pkcs11.C_WrapKey(session, ref wrapMechanism, senderDerivedKeyId, sessionKeyId, null, ref wrappedKeyLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(wrappedKeyLen > 0);

                byte[] wrappedKey = new byte[wrappedKeyLen];

                // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                rv = pkcs11.C_WrapKey(session, ref wrapMechanism, senderDerivedKeyId, sessionKeyId, wrappedKey, ref wrappedKeyLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выработка общего ключа на стороне получателя
                NativeULong recipientDerivedKeyId = CK.CK_INVALID_HANDLE;
                Helpers.Derive_GostR3410_12_Key(pkcs11, session, senderPubKeyId, recipientPrivKeyId, ukm, ref recipientDerivedKeyId);

                // Шаблон демаскированного ключа
                CK_ATTRIBUTE[] unwrappedKeyTemplate = new CK_ATTRIBUTE[8];
                unwrappedKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                unwrappedKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.UnwrappedGost28147_89KeyLabel);
                unwrappedKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
                unwrappedKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
                unwrappedKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
                unwrappedKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
                unwrappedKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
                unwrappedKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

                // Демаскирование сессионного ключа с помощью общего выработанного
                // ключа на стороне получателя
                NativeULong unwrappedKeyId = 0;
                rv = pkcs11.C_UnwrapKey(session, ref wrapMechanism, recipientDerivedKeyId, wrappedKey, wrappedKeyLen,
                    unwrappedKeyTemplate, Convert.ToUInt32(unwrappedKeyTemplate.Length), ref unwrappedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                CK_ATTRIBUTE[] valueTemplate = new CK_ATTRIBUTE[1];
                valueTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_VALUE);
                // In LowLevelAPI we have to allocate unmanaged memory for attribute value
                valueTemplate[0].value = UnmanagedMemory.Allocate(Convert.ToInt32(32));
                valueTemplate[0].valueLen = 32;

                // Get attribute value in second call
                rv = pkcs11.C_GetAttributeValue(session, unwrappedKeyId, valueTemplate, Convert.ToUInt32(valueTemplate.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Сравнение ключа
                byte[] unwrappedKey = UnmanagedMemory.Read(valueTemplate[0].value, Convert.ToInt32(valueTemplate[0].valueLen));
                Assert.IsTrue(Convert.ToBase64String(sessionKeyValue) == Convert.ToBase64String(unwrappedKey));

                // Освобождение выделенной памяти для параметров механизма
                UnmanagedMemory.Free(ref wrapMechanismParams.Data);
                wrapMechanismParams.Len = 0;
                UnmanagedMemory.Free(ref wrapMechanism.Parameter);
                wrapMechanism.ParameterLen = 0;

                // Удаляем созданные пары ключей
                rv = pkcs11.C_DestroyObject(session, senderPrivKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, senderPubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientPrivKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientPubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Удаляем сессионный ключ
                rv = pkcs11.C_DestroyObject(session, sessionKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Удаляем наследованные ключи
                rv = pkcs11.C_DestroyObject(session, senderDerivedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientDerivedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Закрываем сессию
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
        [Test()]
        public void _LL_25_26_03_KegKexp15KuznechikTwisted_Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs40);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Генерация параметра для структуры типа CK_VENDOR_GOST_KEG_PARAMS
                // для выработки двойственного ключа экспорта
                byte[] ukm = new byte[Settings.KEG_256_UKM_LENGTH];
                rv = pkcs11.C_GenerateRandom(session, ukm, Convert.ToUInt32(ukm.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация значения сессионного ключа
                byte[] sessionKeyValue = new byte[Settings.GOST_28147_KEY_SIZE];
                rv = pkcs11.C_GenerateRandom(session, sessionKeyValue, Convert.ToUInt32(sessionKeyValue.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2012(256) отправителя
                NativeULong senderPubKeyId = CK.CK_INVALID_HANDLE;
                NativeULong senderPrivKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGost256KeyPair(pkcs11, session, ref senderPubKeyId, ref senderPrivKeyId, Settings.GostKeyPairId1);

                // Генерация ключевой пары ГОСТ Р 34.10-2012(256) получателя
                NativeULong recipientPubKeyId = CK.CK_INVALID_HANDLE;
                NativeULong recipientPrivKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGost256KeyPair(pkcs11, session, ref recipientPubKeyId, ref recipientPrivKeyId, Settings.GostKeyPairId2);

                // Выработка общего ключа на стороне отправителя
                NativeULong senderDerivedKeyId = CK.CK_INVALID_HANDLE;
                Helpers.DeriveKuznechikTwin_GostR3410_12_Key(pkcs11, session, recipientPubKeyId, senderPrivKeyId, ukm, ref senderDerivedKeyId);

                // Шаблон для создания маскируемого ключа
                CK_ATTRIBUTE[] sessionKeyTemplate = new CK_ATTRIBUTE[9];
                sessionKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                sessionKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.WrappedKuznechikKeyLabel);
                sessionKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (CKK) Extended_CKK.CKK_KUZNECHIK);
                sessionKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
                sessionKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
                sessionKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
                sessionKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_VALUE, sessionKeyValue);
                sessionKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
                sessionKeyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

                // Выработка ключа, который будет замаскирован
                NativeULong sessionKeyId = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_CreateObject(session, sessionKeyTemplate, Convert.ToUInt32(sessionKeyTemplate.Length), ref sessionKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(sessionKeyId != CK.CK_INVALID_HANDLE);

                // Генерация имитовставки для алгоритма экспорта ключей KExp15
                byte[] kexp15Ukm = new byte[Settings.KEXP15_KUZNECHIK_TWIN_UKM_LENGTH];
                rv = pkcs11.C_GenerateRandom(session, kexp15Ukm, Convert.ToUInt32(kexp15Ukm.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                CK_MECHANISM wrapMechanism = CkmUtils.CreateMechanism((NativeULong)Extended_CKM.CKM_KUZNECHIK_KEXP_15_WRAP, kexp15Ukm);

                // Получение длины маскированного ключа
                NativeULong wrappedKeyLen = 0;
                rv = pkcs11.C_WrapKey(session, ref wrapMechanism, senderDerivedKeyId, sessionKeyId, null, ref wrappedKeyLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(wrappedKeyLen > 0);

                byte[] wrappedKey = new byte[wrappedKeyLen];

                // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                rv = pkcs11.C_WrapKey(session, ref wrapMechanism, senderDerivedKeyId, sessionKeyId, wrappedKey, ref wrappedKeyLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выработка общего ключа на стороне получателя
                NativeULong recipientDerivedKeyId = CK.CK_INVALID_HANDLE;
                Helpers.DeriveKuznechikTwin_GostR3410_12_Key(pkcs11, session, senderPubKeyId, recipientPrivKeyId, ukm, ref recipientDerivedKeyId);

                // Шаблон демаскированного ключа
                CK_ATTRIBUTE[] unwrappedKeyTemplate = new CK_ATTRIBUTE[8];
                unwrappedKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
                unwrappedKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.UnwrappedGost28147_89KeyLabel);
                unwrappedKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
                unwrappedKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
                unwrappedKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
                unwrappedKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
                unwrappedKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
                unwrappedKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

                // Демаскирование сессионного ключа с помощью общего выработанного
                // ключа на стороне получателя
                NativeULong unwrappedKeyId = 0;
                rv = pkcs11.C_UnwrapKey(session, ref wrapMechanism, recipientDerivedKeyId, wrappedKey, wrappedKeyLen,
                    unwrappedKeyTemplate, Convert.ToUInt32(unwrappedKeyTemplate.Length), ref unwrappedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                CK_ATTRIBUTE[] valueTemplate = new CK_ATTRIBUTE[1];
                valueTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_VALUE);
                valueTemplate[0].value = UnmanagedMemory.Allocate(Convert.ToInt32(32));
                valueTemplate[0].valueLen = 32;

                rv = pkcs11.C_GetAttributeValue(session, unwrappedKeyId, valueTemplate, Convert.ToUInt32(valueTemplate.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Сравнение ключа
                byte[] unwrappedKey = UnmanagedMemory.Read(valueTemplate[0].value, Convert.ToInt32(valueTemplate[0].valueLen));
                Assert.IsTrue(Convert.ToBase64String(sessionKeyValue) == Convert.ToBase64String(unwrappedKey));

                // Освобождение выделенной памяти под аттрибуты
                for (int i = 0; i < valueTemplate.Length; i++)
                {
                    UnmanagedMemory.Free(ref valueTemplate[i].value);
                    valueTemplate[i].valueLen = 0;
                }

                for (int i = 0; i < sessionKeyTemplate.Length; i++)
                {
                    UnmanagedMemory.Free(ref sessionKeyTemplate[i].value);
                    sessionKeyTemplate[i].valueLen = 0;
                }

                for (int i = 0; i < unwrappedKeyTemplate.Length; i++)
                {
                    UnmanagedMemory.Free(ref unwrappedKeyTemplate[i].value);
                    unwrappedKeyTemplate[i].valueLen = 0;
                }

                // Удаляем созданные пары ключей
                rv = pkcs11.C_DestroyObject(session, senderPrivKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, senderPubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientPrivKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientPubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Удаляем сессионный ключ
                rv = pkcs11.C_DestroyObject(session, sessionKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Удаляем наследованные ключи
                rv = pkcs11.C_DestroyObject(session, senderDerivedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, recipientDerivedKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Закрываем сессию
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
