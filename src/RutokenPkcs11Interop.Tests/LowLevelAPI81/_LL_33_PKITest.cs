using System;
using System.Runtime.InteropServices;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using Net.RutokenPkcs11Interop.Helpers;
using Net.RutokenPkcs11Interop.LowLevelAPI81;

using NativeULong = System.UInt64;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI81
{
    [TestFixture()]
    public class _LL_33_PKITest
    {
        [Test()]
        public void _LL_33_01_CreateCSR_PKCS10Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt64(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2001
                NativeULong pubKeyId = CK.CK_INVALID_HANDLE;
                NativeULong privKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGostKeyPair(pkcs11, session, ref pubKeyId, ref privKeyId, Settings.GostKeyPairId1);

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

                IntPtr[] dnPtr = StringArrayHelpers.ConvertStringArrayToIntPtrArray(dn);
                IntPtr[] extsPtr = StringArrayHelpers.ConvertStringArrayToIntPtrArray(exts);

                IntPtr csr;
                NativeULong csrLength;

                rv = pkcs11.C_EX_CreateCSR(session, pubKeyId,
                    dnPtr, (NativeULong)dnPtr.Length,
                    out csr, out csrLength,
                    privKeyId,
                    null, 0,
                    extsPtr, (NativeULong)extsPtr.Length);

                StringArrayHelpers.FreeUnmanagedIntPtrArray(dnPtr);
                StringArrayHelpers.FreeUnmanagedIntPtrArray(extsPtr);

                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                var csrString = PKIHelpers.GetBase64CSR(csr, (int)csrLength);

                Assert.IsTrue(csrString.Length > 0);

                // Очистка памяти, выделенной для полученного буфера
                rv = pkcs11.C_EX_FreeBuffer(csr);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, pubKeyId);
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
        public void _LL_33_02_ImportCertificateTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt64(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Получение сохраненного тестового сертификата в формате base64
                string certificateBase64 = TestData.PKI_Certificate;

                // Перекодирование в DER
                byte[] certificateDer = PKIHelpers.GetDerFromBase64(certificateBase64);

                // Импорт сертификата
                NativeULong certificateId = CK.CK_INVALID_HANDLE;
                Helpers.PKI_ImportCertificate(pkcs11, session, certificateDer, ref certificateId);

                // Получение информации о сертификате
                IntPtr certificateInfo;
                NativeULong certificateInfoLen;
                rv = pkcs11.C_EX_GetCertificateInfoText(session, certificateId, out certificateInfo, out certificateInfoLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(certificateInfoLen > 0);

                // Получение массива символов
                // Далее нужно воспользоваться функцией ConvertUtils.BytesToUtf8String(),
                // чтобы получить строку
                byte[] certificateInfoArray = new byte[certificateInfoLen];
                Marshal.Copy(certificateInfo, certificateInfoArray, 0, (int)certificateInfoLen);

                // Очистка памяти токена
                rv = pkcs11.C_EX_FreeBuffer(certificateInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Удаление созданного сертификата
                rv = pkcs11.C_DestroyObject(session, certificateId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии работы с токеном
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
