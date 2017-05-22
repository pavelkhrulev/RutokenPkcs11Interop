using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using RutokenPkcs11Interop.LowLevelAPI41;

namespace RutokenPkcs11InteropTests.LowLevelAPI41
{
    static class StringExtensions
    {
        public static IEnumerable<string> SplitInParts(this string s, int partLength)
        {
            if (s == null)
                throw new ArgumentNullException("s");
            if (partLength <= 0)
                throw new ArgumentException();

            for (var i = 0; i < s.Length; i += partLength)
                yield return s.Substring(i, Math.Min(partLength, s.Length - i));
        }
    }

    [TestClass]
    public class _LL41_33_PKITest
    {
        private string GetBase64CSR(IntPtr csr, int csrLength)
        {
            var base64CSR = new StringBuilder();
            base64CSR.AppendLine("-----BEGIN NEW CERTIFICATE REQUEST-----");

            byte[] managedArray = new byte[csrLength];
            Marshal.Copy(csr, managedArray, 0, (int)csrLength);

            var request = ConvertUtils.BytesToBase64String(managedArray);
            var strings = request.SplitInParts(64);
            foreach (var line in strings)
            {
                base64CSR.AppendLine(line);
            }
            base64CSR.AppendLine("-----END NEW CERTIFICATE REQUEST-----");

            return base64CSR.ToString();
        }

        [TestMethod]
        public void _LL41_33_01_CreateCSR_PKCS10Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2001
                uint pubKeyId = CK.CK_INVALID_HANDLE;
                uint privKeyId = CK.CK_INVALID_HANDLE;
                rv = Helpers.GenerateGostKeyPair(pkcs11, session, ref pubKeyId, ref privKeyId, Settings.GostKeyPairId1);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Создание запроса на сертификат
                List<string> dn = new List<string>()
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

                List<string> exts = new List<string>()
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

                IntPtr csr;
                uint csrLength;

                var dnArray = dn.ToArray();
                var extsArray = exts.ToArray();

                IntPtr[] dn_array_intptr = new IntPtr[dnArray.Length];
                IntPtr[] exts_array_intptr = new IntPtr[extsArray.Length];

                for (int i = 0; i < dnArray.Length; i++)
                {
                    var utf8stringBytes = ConvertUtils.Utf8StringToBytes(dnArray[i], dnArray[i].Length + 4, 0x0);
                    dn_array_intptr[i] = Marshal.AllocHGlobal(utf8stringBytes.Length);
                    Marshal.Copy(utf8stringBytes, 0, dn_array_intptr[i], utf8stringBytes.Length);
                }

                for (int i = 0; i < extsArray.Length; i++)
                {
                    var utf8stringBytes = ConvertUtils.Utf8StringToBytes(extsArray[i], extsArray[i].Length + 4, 0x0);
                    exts_array_intptr[i] = Marshal.AllocHGlobal(utf8stringBytes.Length);
                    Marshal.Copy(utf8stringBytes, 0, exts_array_intptr[i], utf8stringBytes.Length);
                }

                GCHandle gcDn = GCHandle.Alloc(dn_array_intptr, GCHandleType.Pinned);
                GCHandle gcExts = GCHandle.Alloc(exts_array_intptr, GCHandleType.Pinned);

                var test1 = gcDn.AddrOfPinnedObject();

                rv = pkcs11.C_EX_CreateCSR(session, pubKeyId,
                    gcDn.AddrOfPinnedObject(), (uint)dn_array_intptr.Length,
                    out csr, out csrLength,
                    privKeyId,
                    IntPtr.Zero, 0,
                    gcExts.AddrOfPinnedObject(), (uint)exts_array_intptr.Length);

                File.WriteAllText("test_cert_req.txt", GetBase64CSR(csr, (int) csrLength));

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
