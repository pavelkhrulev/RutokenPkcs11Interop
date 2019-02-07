using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestClass]
    public class _HL_31_LicenseTest
    {
        [TestMethod]
        public void _HL_31_01_SetAndGetLicenseTest()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации администратора
                    session.Login(CKU.CKU_SO, Settings.SecurityOfficerPin);

                    // Сохранение лицензии
                    uint licenseNum = 1;
                    byte[] setlicense = new byte[RutokenPkcs11Interop.Settings.DefaultLicenseLength];
                    (new Random()).NextBytes(setlicense);
                    session.SetLicense(licenseNum, setlicense);

                    // Чтение лицензии
                    byte[] getLicense = session.GetLicense(licenseNum);

                    // Проверка на совпадение записанной и прочитанной лицензии
                    Assert.IsTrue(Convert.ToBase64String(setlicense) == Convert.ToBase64String(getLicense));
                }
            }
        }
    }
}
