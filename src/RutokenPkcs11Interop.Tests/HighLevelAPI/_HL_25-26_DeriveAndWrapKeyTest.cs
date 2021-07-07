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
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.WrappedGost28147_89KeyLabel),
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
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.UnwrappedGost28147_89KeyLabel),
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
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.WrappedGost28147_89KeyLabel),
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
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.UnwrappedGost28147_89KeyLabel),
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
        public void _HL_25_26_03_KegKexp15KuznechikTwisted_Test()
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

                    // Генерация имитовставки для структуры механизма Keg(256)
                    // для выработки общего ключа
                    byte[] ukm = session.GenerateRandom(Settings.KEG_256_UKM_LENGTH);

                    // Генерация значения сессионного ключа
                    byte[] sessionKeyValue = session.GenerateRandom(Settings.GOST_28147_KEY_SIZE);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 (256 бит) отправителя
                    IObjectHandle senderPublicKeyHandle = null;
                    IObjectHandle senderPrivateKeyHandle = null;
                    Helpers.GenerateGost256KeyPair(session, out senderPublicKeyHandle, out senderPrivateKeyHandle, Settings.GostKeyPairId1);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 (256 бит) получателя
                    IObjectHandle recipientPublicKeyHandle = null;
                    IObjectHandle recipientPrivateKeyHandle = null;
                    Helpers.GenerateGost256KeyPair(session, out recipientPublicKeyHandle, out recipientPrivateKeyHandle, Settings.GostKeyPairId2);

                    // Выработка общего ключа на стороне отправителя
                    IObjectHandle senderDerivedTwinKeyHandle = null;
                    Helpers.DeriveKuznechikTwin_GostR3410_12_Key(session, recipientPublicKeyHandle, senderPrivateKeyHandle, ukm, out senderDerivedTwinKeyHandle);

                    // Шаблон для создания маскируемого ключа
                    var sessionKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.WrappedKuznechikKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (CKK) Extended_CKK.CKK_KUZNECHIK),
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

                    // Генерация имитовставки для механизма KExp15 на двойственном ключе типа Кузнечик
                    // для выработки общего ключа
                    byte[] kexp15Ukm = session.GenerateRandom(Settings.KEXP15_KUZNECHIK_TWIN_UKM_LENGTH);

                    // Определение параметров механизма маскирования
                    var wrapMechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_KUZNECHIK_KEXP_15_WRAP, kexp15Ukm);

                    // Маскирование ключа на общем ключе, выработанном на стороне отправителя
                    byte[] wrappedKey = session.WrapKey(wrapMechanism, senderDerivedTwinKeyHandle, sessionKeyHandle);

                    // Выработка общего ключа на стороне получателя
                    IObjectHandle recipientDerivedKeyHandle = null;
                    Helpers.DeriveKuznechikTwin_GostR3410_12_Key(session, senderPublicKeyHandle, recipientPrivateKeyHandle, ukm, out recipientDerivedKeyHandle);

                    // Шаблон демаскированного ключа
                    var unwrappedKeyAttributes = new List<IObjectAttribute>()
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.UnwrappedKuznechikKeyLabel),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (CKK)Extended_CKK.CKK_KUZNECHIK),
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
                    session.DestroyObject(senderDerivedTwinKeyHandle);
                    session.DestroyObject(recipientDerivedKeyHandle);

                    // Удаляем размаскированный ключ
                    session.DestroyObject(unwrappedKeyHandle);

                    // Закрываем сессию
                    session.Logout();
                }
            }
        }
    }
}
