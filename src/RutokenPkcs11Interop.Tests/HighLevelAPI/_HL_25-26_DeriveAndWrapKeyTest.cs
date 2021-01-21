using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using NUnit.Framework;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_25_26_DeriveAndWrapKeyTest
    {
        [Test()]
        public void _HL_25_26_01_DeriveAndWrap_VKO_Gost3410_01_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                    // для выработки общего ключа
                    byte[] ukm = session.GenerateRandom(Settings.UKM_LENGTH);

                    // Генерация значения сессионного ключа
                    byte[] sessionKeyValue = session.GenerateRandom(Settings.GOST_28147_KEY_SIZE);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001 отправителя
                    IObjectHandle senderPublicKeyHandle = null;
                    IObjectHandle senderPrivateKeyHandle = null;
                    Helpers.GenerateGostKeyPair(session, out senderPublicKeyHandle, out senderPrivateKeyHandle, Settings.GostKeyPairId1);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001 получателя
                    IObjectHandle recipientPublicKeyHandle = null;
                    IObjectHandle recipientPrivateKeyHandle = null;
                    Helpers.GenerateGostKeyPair(session, out recipientPublicKeyHandle, out recipientPrivateKeyHandle, Settings.GostKeyPairId2);

                    // Выработка общего ключа на стороне отправителя
                    IObjectHandle senderDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_Key(session, recipientPublicKeyHandle, senderPrivateKeyHandle, ukm, out senderDerivedKeyHandle);

                    // Шаблон для создания маскируемого ключа
                    var sessionKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.WrappedKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, sessionKeyValue),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
                    };

                    // Выработка ключа, который будет замаскирован
                    IObjectHandle sessionKeyHandle = null;
                    sessionKeyHandle = session.CreateObject(sessionKeyAttributes);

                    // Определение параметров механизма маскирования
                    var wrapMechanismParams = Settings.Factories.MechanismParamsFactory.CreateCkKeyDerivationStringData(ukm);
                    var wrapMechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                    // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                    byte[] wrappedKey = session.WrapKey(wrapMechanism, senderDerivedKeyHandle, sessionKeyHandle);

                    // Выработка общего ключа на стороне получателя
                    IObjectHandle recipientDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_Key(session, senderPublicKeyHandle, recipientPrivateKeyHandle, ukm, out recipientDerivedKeyHandle);

                    // Шаблон демаскированного ключа
                    var unwrappedKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.UnwrappedKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
                    };

                    // Демаскирование сессионного ключа с помощью общего выработанного
                    // ключа на стороне получателя
                    IObjectHandle unwrappedKeyHandle = session.UnwrapKey(wrapMechanism, recipientDerivedKeyHandle, wrappedKey, unwrappedKeyAttributes);

                    // Сравнение ключа
                    // Получаем публичный ключ по его Id
                    var attributes = new List<CKA>
                    {
                        CKA.CKA_VALUE
                    };
                    List<IObjectAttribute> unwrappedKeyValueAttribute = session.GetAttributeValue(unwrappedKeyHandle, attributes);

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

                    // Удаляем размаскированный ключ
                    session.DestroyObject(unwrappedKeyHandle);

                    // Закрываем сессию
                    session.Logout();
                }
            }
        }

        [Test()]
        public void _HL_25_26_02_DeriveAndWrap_VKO_Gost3410_12_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                    // для выработки общего ключа
                    byte[] ukm = session.GenerateRandom(Settings.UKM_LENGTH);

                    // Генерация значения сессионного ключа
                    byte[] sessionKeyValue = session.GenerateRandom(Settings.GOST_28147_KEY_SIZE);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 отправителя
                    IObjectHandle senderPublicKeyHandle = null;
                    IObjectHandle senderPrivateKeyHandle = null;
                    Helpers.GenerateGost512KeyPair(session, out senderPublicKeyHandle, out senderPrivateKeyHandle, Settings.GostKeyPairId1);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 получателя
                    IObjectHandle recipientPublicKeyHandle = null;
                    IObjectHandle recipientPrivateKeyHandle = null;
                    Helpers.GenerateGost512KeyPair(session, out recipientPublicKeyHandle, out recipientPrivateKeyHandle, Settings.GostKeyPairId2);

                    // Выработка общего ключа на стороне отправителя
                    IObjectHandle senderDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_12_Key(session, recipientPublicKeyHandle, senderPrivateKeyHandle, ukm, out senderDerivedKeyHandle);

                    // Шаблон для создания маскируемого ключа
                    var sessionKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.WrappedKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, sessionKeyValue),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
                    };

                    // Выработка ключа, который будет замаскирован
                    IObjectHandle sessionKeyHandle = null;
                    sessionKeyHandle = session.CreateObject(sessionKeyAttributes);

                    // Определение параметров механизма маскирования
                    var wrapMechanismParams = Settings.Factories.MechanismParamsFactory.CreateCkKeyDerivationStringData(ukm);
                    var wrapMechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_KEY_WRAP, wrapMechanismParams);

                    // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                    byte[] wrappedKey = session.WrapKey(wrapMechanism, senderDerivedKeyHandle, sessionKeyHandle);

                    // Выработка общего ключа на стороне получателя
                    IObjectHandle recipientDerivedKeyHandle = null;
                    Helpers.Derive_GostR3410_12_Key(session, senderPublicKeyHandle, recipientPrivateKeyHandle, ukm, out recipientDerivedKeyHandle);

                    // Шаблон демаскированного ключа
                    var unwrappedKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.UnwrappedKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false),
                    };

                    // Демаскирование сессионного ключа с помощью общего выработанного
                    // ключа на стороне получателя
                    IObjectHandle unwrappedKeyHandle = session.UnwrapKey(wrapMechanism, recipientDerivedKeyHandle, wrappedKey, unwrappedKeyAttributes);

                    // Сравнение ключа
                    // Получаем публичный ключ по его Id
                    var attributes = new List<CKA>
                    {
                        CKA.CKA_VALUE
                    };
                    List<IObjectAttribute> unwrappedKeyValueAttribute = session.GetAttributeValue(unwrappedKeyHandle, attributes);

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

        [Test()]
        public void _HL_25_26_03_ExtendedWrap_VKO_Gost3410_12_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 отправителя
                    IObjectHandle senderPublicKeyHandle = null;
                    IObjectHandle senderPrivateKeyHandle = null;
                    Helpers.GenerateGost512KeyPair(session, out senderPublicKeyHandle, out senderPrivateKeyHandle,
                        Settings.GostKeyPairId1);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 получателя
                    IObjectHandle recipientPublicKeyHandle = null;
                    IObjectHandle recipientPrivateKeyHandle = null;
                    Helpers.GenerateGost512KeyPair(session, out recipientPublicKeyHandle, out recipientPrivateKeyHandle,
                        Settings.GostKeyPairId2);

                    // Шаблон для создания маскируемого ключа
                    var sessionKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.WrappedKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true)
                    };

                    // Генерация параметра для структуры типа CK_GOSTR3410_DERIVE_PARAMS
                    // для выработки общего ключа
                    byte[] ukm = session.GenerateRandom(Settings.UKM_LENGTH);

                    // Определение механизма генерации ключа для маскирования
                    var generationMechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_KEY_GEN);

                    // Получаем публичный ключ по его Id
                    var publicKeyAttributeNames = new List<CKA>
                    {
                        CKA.CKA_VALUE
                    };
                    List<IObjectAttribute> publicKeyAttributes = session.GetAttributeValue(recipientPublicKeyHandle, publicKeyAttributeNames);

                    // Определение параметров механизма наследования ключа
                    var deriveMechanismParams = Settings.Factories.RutokenMechanismParamsFactory.CreateCkGostR3410_12_DeriveParams(
                            (ulong) Extended_CKM.CKM_KDF_GOSTR3411_2012_256, publicKeyAttributes[0].GetValueAsByteArray(), ukm);

                    // Определяем механизм наследования ключа
                    var derivationMechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3410_12_DERIVE, deriveMechanismParams);

                    // Определение параметров механизма маскирования
                    var wrapMechanismParams = Settings.Factories.MechanismParamsFactory.CreateCkKeyDerivationStringData(ukm);
                    var wrappingMechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_KEY_WRAP,
                        wrapMechanismParams);

                    // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                    IObjectHandle sessionKeyHandle = null;
                    byte[] wrappedKey = session.ExtendedWrapKey(generationMechanism, sessionKeyAttributes,
                        derivationMechanism, senderPrivateKeyHandle, wrappingMechanism, ref sessionKeyHandle);

                    // Шаблон демаскированного ключа
                    var unwrappedKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.UnwrappedKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true)
                    };

                    // Демаскирование сессионного ключа с помощью общего выработанного
                    // ключа на стороне получателя
                    IObjectHandle unwrappedKeyHandle = session.ExtendedUnwrapKey(derivationMechanism, senderPublicKeyHandle,
                        wrappingMechanism, wrappedKey, unwrappedKeyAttributes);

                    // Сравнение ключа
                    // Получаем публичный ключ по его Id
                    List<CKA> attributes = new List<CKA>
                    {
                        CKA.CKA_VALUE
                    };
                    List<IObjectAttribute> unwrappedKeyValueAttribute = session.GetAttributeValue(unwrappedKeyHandle,
                        attributes);
                    List<IObjectAttribute> sessionKeyValueAttribute = session.GetAttributeValue(sessionKeyHandle,
                        attributes);

                    Assert.IsTrue(Convert.ToBase64String(sessionKeyValueAttribute[0].GetValueAsByteArray()) ==
                                  Convert.ToBase64String(unwrappedKeyValueAttribute[0].GetValueAsByteArray()));

                    // Удаляем созданные пары ключей
                    session.DestroyObject(senderPublicKeyHandle);
                    session.DestroyObject(senderPrivateKeyHandle);
                    session.DestroyObject(recipientPublicKeyHandle);
                    session.DestroyObject(recipientPrivateKeyHandle);

                    // Удаляем сессионный ключ
                    session.DestroyObject(sessionKeyHandle);

                    // Закрываем сессию
                    session.Logout();
                }
            }
        }
    }
}
