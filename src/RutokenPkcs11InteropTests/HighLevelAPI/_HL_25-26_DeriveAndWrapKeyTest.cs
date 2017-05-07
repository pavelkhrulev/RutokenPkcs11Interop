using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestClass]
    public class _HL_25_26_DeriveAndWrapKeyTest
    {
        [TestMethod]
        public void _HL_25_26_01_DeriveAndWrap_VKO_Gost3410_01_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                    // для выработки общего ключа
                    byte[] ukm = session.GenerateRandom(Settings.UKM_LENGTH);

                    // Генерация значения сессионного ключа
                    byte[] sessionKeyValue = session.GenerateRandom(Settings.GOST_28147_KEY_SIZE);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001 отправителя
                    ObjectHandle senderPublicKeyHandle = null;
                    ObjectHandle senderPrivateKeyHandle = null;
                    Helpers.GenerateGostKeyPair(session, out senderPublicKeyHandle, out senderPrivateKeyHandle, Settings.GostKeyPairId1);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001 получателя
                    ObjectHandle recipientPublicKeyHandle = null;
                    ObjectHandle recipientPrivateKeyHandle = null;
                    Helpers.GenerateGostKeyPair(session, out recipientPublicKeyHandle, out recipientPrivateKeyHandle, Settings.GostKeyPairId2);

                    // Выработка общего ключа на стороне отправителя
                    ObjectHandle senderDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_Key(session, recipientPublicKeyHandle, senderPrivateKeyHandle, ukm, out senderDerivedKeyHandle);

                    // Шаблон для создания маскируемого ключа
                    var sessionKeyAttributes = new List<ObjectAttribute>()
                    {
                        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        new ObjectAttribute(CKA.CKA_LABEL, Settings.WrappedKeyLabel),
                        new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
                        new ObjectAttribute(CKA.CKA_TOKEN, false),
                        new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                        new ObjectAttribute(CKA.CKA_PRIVATE, true),
                        new ObjectAttribute(CKA.CKA_VALUE, sessionKeyValue),
                        new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
                        new ObjectAttribute(CKA.CKA_SENSITIVE, false),
                    };

                    // Выработка ключа, который будет замаскирован
                    ObjectHandle sessionKeyHandle = null;
                    sessionKeyHandle = session.CreateObject(sessionKeyAttributes);

                    // Определение параметров механизма маскирования
                    var wrapMechanismParams = new CkKeyDerivationStringData(ukm);
                    var wrapMechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                    // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                    byte[] wrappedKey = session.WrapKey(wrapMechanism, senderDerivedKeyHandle, sessionKeyHandle);

                    // Выработка общего ключа на стороне получателя
                    ObjectHandle recipientDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_Key(session, senderPublicKeyHandle, recipientPrivateKeyHandle, ukm, out recipientDerivedKeyHandle);

                    // Шаблон демаскированного ключа
                    var unwrappedKeyAttributes = new List<ObjectAttribute>()
                    {
                        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        new ObjectAttribute(CKA.CKA_LABEL, Settings.UnwrappedKeyLabel),
                        new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
                        new ObjectAttribute(CKA.CKA_TOKEN, false),
                        new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                        new ObjectAttribute(CKA.CKA_PRIVATE, true),
                        new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
                        new ObjectAttribute(CKA.CKA_SENSITIVE, false),
                    };

                    // Демаскирование сессионного ключа с помощью общего выработанного
                    // ключа на стороне получателя
                    ObjectHandle unwrappedKeyHandle = session.UnwrapKey(wrapMechanism, recipientDerivedKeyHandle, wrappedKey, unwrappedKeyAttributes);

                    // Сравнение ключа
                    // Получаем публичный ключ по его Id
                    var attributes = new List<CKA>
                    {
                        CKA.CKA_VALUE
                    };
                    List<ObjectAttribute> unwrappedKeyValueAttribute = session.GetAttributeValue(unwrappedKeyHandle, attributes);

                    Assert.IsTrue(Convert.ToBase64String(sessionKeyValue) ==
                            Convert.ToBase64String(unwrappedKeyValueAttribute[0].GetValueAsByteArray()));

                    // Удаляем созданные пары ключей
                    session.DestroyObject(senderPublicKeyHandle);
                    session.DestroyObject(senderPrivateKeyHandle);
                    session.DestroyObject(recipientPublicKeyHandle);
                    session.DestroyObject(recipientPrivateKeyHandle);

                    // Удаляем сессионный ключ
                    session.DestroyObject(sessionKeyHandle);

                    // Удаляем наследованные ключи
                    session.DestroyObject(senderDerivedKeyHandle);
                    session.DestroyObject(recipientDerivedKeyHandle);

                    // Закрываем сессию
                    session.Logout();
                }
            }
        }

        [TestMethod]
        public void _HL_25_26_02_DeriveAndWrap_VKO_Gost3410_12_Test()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                    // для выработки общего ключа
                    byte[] ukm = session.GenerateRandom(Settings.UKM_LENGTH);

                    // Генерация значения сессионного ключа
                    byte[] sessionKeyValue = session.GenerateRandom(Settings.GOST_28147_KEY_SIZE);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 отправителя
                    ObjectHandle senderPublicKeyHandle = null;
                    ObjectHandle senderPrivateKeyHandle = null;
                    Helpers.GenerateGost512KeyPair(session, out senderPublicKeyHandle, out senderPrivateKeyHandle, Settings.GostKeyPairId1);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 получателя
                    ObjectHandle recipientPublicKeyHandle = null;
                    ObjectHandle recipientPrivateKeyHandle = null;
                    Helpers.GenerateGost512KeyPair(session, out recipientPublicKeyHandle, out recipientPrivateKeyHandle, Settings.GostKeyPairId2);

                    // Выработка общего ключа на стороне отправителя
                    ObjectHandle senderDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_12_Key(session, recipientPublicKeyHandle, senderPrivateKeyHandle, ukm, out senderDerivedKeyHandle);

                    // Шаблон для создания маскируемого ключа
                    var sessionKeyAttributes = new List<ObjectAttribute>()
                    {
                        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        new ObjectAttribute(CKA.CKA_LABEL, Settings.WrappedKeyLabel),
                        new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
                        new ObjectAttribute(CKA.CKA_TOKEN, false),
                        new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                        new ObjectAttribute(CKA.CKA_PRIVATE, true),
                        new ObjectAttribute(CKA.CKA_VALUE, sessionKeyValue),
                        new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
                        new ObjectAttribute(CKA.CKA_SENSITIVE, false),
                    };

                    // Выработка ключа, который будет замаскирован
                    ObjectHandle sessionKeyHandle = null;
                    sessionKeyHandle = session.CreateObject(sessionKeyAttributes);

                    // Определение параметров механизма маскирования
                    var wrapMechanismParams = new CkKeyDerivationStringData(ukm);
                    var wrapMechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                    // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                    byte[] wrappedKey = session.WrapKey(wrapMechanism, senderDerivedKeyHandle, sessionKeyHandle);

                    // Выработка общего ключа на стороне получателя
                    ObjectHandle recipientDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_12_Key(session, senderPublicKeyHandle, recipientPrivateKeyHandle, ukm, out recipientDerivedKeyHandle);

                    // Шаблон демаскированного ключа
                    var unwrappedKeyAttributes = new List<ObjectAttribute>()
                    {
                        new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        new ObjectAttribute(CKA.CKA_LABEL, Settings.UnwrappedKeyLabel),
                        new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
                        new ObjectAttribute(CKA.CKA_TOKEN, false),
                        new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                        new ObjectAttribute(CKA.CKA_PRIVATE, true),
                        new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
                        new ObjectAttribute(CKA.CKA_SENSITIVE, false),
                    };

                    // Демаскирование сессионного ключа с помощью общего выработанного
                    // ключа на стороне получателя
                    ObjectHandle unwrappedKeyHandle = session.UnwrapKey(wrapMechanism, recipientDerivedKeyHandle, wrappedKey, unwrappedKeyAttributes);

                    // Сравнение ключа
                    // Получаем публичный ключ по его Id
                    var attributes = new List<CKA>
                    {
                        CKA.CKA_VALUE
                    };
                    List<ObjectAttribute> unwrappedKeyValueAttribute = session.GetAttributeValue(unwrappedKeyHandle, attributes);

                    Assert.IsTrue(Convert.ToBase64String(sessionKeyValue) ==
                            Convert.ToBase64String(unwrappedKeyValueAttribute[0].GetValueAsByteArray()));

                    // Удаляем созданные пары ключей
                    session.DestroyObject(senderPublicKeyHandle);
                    session.DestroyObject(senderPrivateKeyHandle);
                    session.DestroyObject(recipientPublicKeyHandle);
                    session.DestroyObject(recipientPrivateKeyHandle);

                    // Удаляем сессионный ключ
                    session.DestroyObject(sessionKeyHandle);

                    // Удаляем наследованные ключи
                    session.DestroyObject(senderDerivedKeyHandle);
                    session.DestroyObject(recipientDerivedKeyHandle);

                    // Закрываем сессию
                    session.Logout();
                }
            }
        }
    }
}
