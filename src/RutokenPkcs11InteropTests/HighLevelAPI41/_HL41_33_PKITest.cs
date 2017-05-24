using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI41;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11InteropTests.HighLevelAPI41
{
    [TestClass]
    public class _HL41_33_PKITest
    {
        [TestMethod]
        public void _HL41_33_02_ImportCertificateTest()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
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
