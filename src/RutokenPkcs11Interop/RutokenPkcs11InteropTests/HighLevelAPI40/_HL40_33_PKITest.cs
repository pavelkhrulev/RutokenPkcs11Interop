using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI40;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.HighLevelAPI40;

namespace RutokenPkcs11InteropTests.HighLevelAPI40
{
    [TestFixture()]
    public class _HL40_33_PKITest
    {
        [Test()]
        public void _HL40_33_01_CreateCSR_PKCS10Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
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
                        "UTF8String:Москва",
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
        public void _HL40_33_02_ImportCertificateTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Получение сохраненного тестового сертификата в формате base64
                    string certificateBase64 = TestData.PKI_Certificate;

                    // Перекодирование в DER
                    byte[] certificateDer = PKIHelpers.GetDerFromBase64(certificateBase64);

                    // Импорт сертификата
                    ObjectHandle certificateHandle;
                    Helpers.PKI_ImportCertificate(session, certificateDer, out certificateHandle);

                    // Получение информации о сертификате
                    string certificateInfo = session.GetCertificateInfoText(certificateHandle);
                    Assert.IsTrue(!string.IsNullOrEmpty(certificateInfo));

                    // Удаление созданного сертификата
                    session.DestroyObject(certificateHandle);

                    session.Logout();
                }
            }
        }
    }
}
