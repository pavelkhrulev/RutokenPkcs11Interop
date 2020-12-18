using System.Collections.Generic;
using System.Linq;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Helpers;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_33_PKITest
    {
        [Test()]
        public void _HL_33_01_CreateCSR_PKCS10Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001
                    IObjectHandle publicKey = null;
                    IObjectHandle privateKey = null;
                    Helpers.GenerateGostKeyPair(session, out publicKey, out privateKey, Settings.GostKeyPairId1);

                    // Создание запроса на сертификат
                    string[] dn =
                    {
                        "CN",
                        "UTF8String:Иванов",
                        "C",
                        "RU",
                        "2.5.4.5",
                        "12312312312",
                        "1.2.840.113549.1.9.1",
                        "ivanov@mail.ru",
                        "ST",
                        "UTF8String:Москва"
                    };

                    string[] exts =
                    {
                        "keyUsage",
                        "digitalSignature,nonRepudiation,keyEncipherment,dataEncipherment",
                        "extendedKeyUsage",
                        "1.2.643.2.2.34.6,1.3.6.1.5.5.7.3.2,1.3.6.1.5.5.7.3.4",
                        "2.5.29.14",
                        "ASN1:FORMAT:HEX,OCTETSTRING:FE117B93CEC6B5065E1613E155D3A9CA597C0F81",
                        "1.2.643.100.111",
                        "ASN1:UTF8String:СКЗИ \\\"Рутокен ЭЦП 2.0\\\""
                    };

                    string csr = session.CreateCSR(publicKey, dn, privateKey, null, exts);

                    Assert.IsTrue(csr.Length > 0);

                    session.Logout();
                }
            }
        }

        [Test()]
        public void _HL_33_02_ImportCertificateTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Получение сохраненного тестового сертификата в формате base64
                    string certificateBase64 = TestData.PKI_Certificate;

                    // Перекодирование в DER
                    byte[] certificateDer = PKIHelpers.GetDerFromBase64(certificateBase64);

                    // Импорт сертификата
                    IObjectHandle certificateHandle;
                    Helpers.PKI_ImportCertificate(session, certificateDer, out certificateHandle, Settings.GostKeyPairId1);

                    // Получение информации о сертификате
                    string certificateInfo = session.GetCertificateInfoText(certificateHandle);
                    Assert.IsTrue(!string.IsNullOrEmpty(certificateInfo));

                    // Удаление созданного сертификата
                    session.DestroyObject(certificateHandle);

                    session.Logout();
                }
            }
        }

        [Test()]
        public void _HL_33_03_PKCS7SignTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Шаблон для поиска закрытого ключа ГОСТ Р 34.10-2001
                    var privateKeyAttributes = new List<IObjectAttribute>
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Settings.GostKeyPairId1),
                   };

                    // Шаблон для поиска сертификата ключа подписи
                    uint tokenUserCertificate = 1;
                    var certificateAttributes = new List<IObjectAttribute>
                    {
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Settings.GostKeyPairId1),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
                        Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_CATEGORY, tokenUserCertificate)
                    };

                    // Данные
                    string signData = "01234";

                    // Поиск закрытого ключа на токене
                    List<IObjectHandle> privateKeys = session.FindAllObjects(privateKeyAttributes);
                    Assert.IsTrue(privateKeys != null);
                    Assert.IsTrue(privateKeys.Count > 0);

                    // Поиск сертификата на токене
                    List<IObjectHandle> certificates = session.FindAllObjects(certificateAttributes);
                    Assert.IsTrue(certificates != null);
                    Assert.IsTrue(certificates.Count > 0);

                    // Подпись данных
                    byte[] signature =
                        session.PKCS7Sign(ConvertUtils.Utf8StringToBytes(signData),
                            certificates[0], privateKeys[0], null, 0);
                    Assert.IsTrue(signature != null);
                    Assert.IsTrue(signature.Length > 0);

                    session.Logout();
                }
            }
        }
    }
}
