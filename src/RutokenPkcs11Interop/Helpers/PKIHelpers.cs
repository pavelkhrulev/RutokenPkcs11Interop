using System;
using System.Runtime.InteropServices;
using System.Text;
using Net.Pkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.Helpers
{
    public static class PKIHelpers
    {
        public static string GetBase64CSR(IntPtr csr, int csrLength)
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

        public static byte[] GetDerFromBase64(string certificateBase64)
        {
            var validCertificate = certificateBase64.Replace("-----BEGIN CERTIFICATE-----", "")
                                                    .Replace("-----END CERTIFICATE-----", "");

            return ConvertUtils.Base64StringToBytes(validCertificate);
        }
    }
}
