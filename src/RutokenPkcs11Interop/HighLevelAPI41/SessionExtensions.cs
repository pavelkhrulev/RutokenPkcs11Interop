using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.LowLevelAPI41;
using HLA41 = Net.Pkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public static class SessionExtensions
    {
        public static void UnblockUserPIN(this HLA41.Session session)
        {
            CKR rv = session.LowLevelPkcs11.C_EX_UnblockUserPIN(session.SessionId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_UnblockUserPIN", rv);
        }

        public static void SetTokenName(this HLA41.Session session, string label)
        {
            var labelArray = ConvertUtils.Utf8StringToBytes(label);
            CKR rv = session.LowLevelPkcs11.C_EX_SetTokenName(session.SessionId, labelArray);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetTokenName", rv);
        }

        public static string GetTokenLabel(this HLA41.Session session)
        {
            uint tokenLabelLength = 0;
            CKR rv = session.LowLevelPkcs11.C_EX_GetTokenName(session.SessionId, null, ref tokenLabelLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetTokenName", rv);

            byte[] tokenLabel = new byte[tokenLabelLength];

            rv = session.LowLevelPkcs11.C_EX_GetTokenName(session.SessionId, tokenLabel, ref tokenLabelLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetTokenName", rv);

            if (tokenLabel.Length != tokenLabelLength)
                Array.Resize(ref tokenLabel, Convert.ToInt32(tokenLabelLength));

            return ConvertUtils.BytesToUtf8String(tokenLabel);
        }

        public static void SetLicense(this HLA41.Session session, uint licenseNum, byte[] license)
        {
            if (!Settings.LicenseAllowedNumbers.Contains(licenseNum))
                throw new ArgumentOutOfRangeException(nameof(licenseNum));

            if (license == null)
                throw new ArgumentNullException(nameof(license));

            CKR rv = session.LowLevelPkcs11.C_EX_SetLicense(
                session.SessionId, licenseNum, license);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetLicense", rv);
        }

        public static byte[] GetLicense(this HLA41.Session session, uint licenseNum)
        {
            if (!Settings.LicenseAllowedNumbers.Contains(licenseNum))
                throw new ArgumentOutOfRangeException(nameof(licenseNum));

            uint licenseLen = 0;
            CKR rv = session.LowLevelPkcs11.C_EX_GetLicense(
                session.SessionId, licenseNum, null, ref licenseLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetLicense", rv);

            if (licenseLen == 0)
                throw new InvalidOperationException("C_EX_GetLicense: no license found");

            byte[] license = new byte[licenseLen];

            rv = session.LowLevelPkcs11.C_EX_GetLicense(
                session.SessionId, licenseNum, license, ref licenseLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetLicense", rv);

            return license;
        }

        public static void LoadActivationKey(this HLA41.Session session, byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            CKR rv = session.LowLevelPkcs11.C_EX_LoadActivationKey(
                session.SessionId, key);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_LoadActivationKey", rv);
        }

        public static byte[] GenerateActivationPassword(this HLA41.Session session,
            ActivationPasswordNumber passwordNumber, ActivationPasswordCharacterSet characterSet)
        {
            // Получение длины пароля активации
            uint passwordLength = 0;
            CKR rv = session.LowLevelPkcs11.C_EX_GenerateActivationPassword(
                session.SessionId, (uint)passwordNumber, null, ref passwordLength, (uint)characterSet);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GenerateActivationPassword", rv);

            if (passwordLength <= 0)
                throw new InvalidOperationException(
                    "C_EX_GenerateActivationPassword: invalid password length");

            // Генерация пароля активации
            byte[] password = new byte[passwordLength];
            rv = session.LowLevelPkcs11.C_EX_GenerateActivationPassword(
                session.SessionId, (uint)passwordNumber, password, ref passwordLength, (uint)characterSet);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GenerateActivationPassword", rv);

            return password;
        }

        public static byte[] SignInvisible(this HLA41.Session session,
            ref HLA41.Mechanism mechanism, HLA41.ObjectHandle keyHandle, byte[] data)
        {
            if (mechanism == null)
                throw new ArgumentNullException(nameof(mechanism));

            if (keyHandle == null)
                throw new ArgumentNullException(nameof(keyHandle));

            if (data == null)
                throw new ArgumentNullException(nameof(data));

            var ckMechanism = new CK_MECHANISM()
            {
                Mechanism = mechanism.Type
            };

            CKR rv = session.LowLevelPkcs11.C_EX_SignInvisibleInit(session.SessionId, ref ckMechanism,
                keyHandle.ObjectId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisibleInit", rv);

            uint signatureLen = 0;
            rv = session.LowLevelPkcs11.C_EX_SignInvisible(session.SessionId, data, Convert.ToUInt32(data.Length), null,
                ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisible", rv);

            byte[] signature = new byte[signatureLen];
            rv = session.LowLevelPkcs11.C_EX_SignInvisible(session.SessionId, data, Convert.ToUInt32(data.Length),
                signature, ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisible", rv);

            if (signature.Length != signatureLen)
                Array.Resize(ref signature, Convert.ToInt32(signatureLen));

            return signature;
        }

        public static string CreateCSR(this HLA41.Session session, HLA41.ObjectHandle publicKey,
            string[] dn, HLA41.ObjectHandle privateKey, string[] attributes, string[] extensions)
        {
            IntPtr[] dnPtr = StringArrayHelpers.ConvertStringArrayToIntPtrArray(dn);
            IntPtr[] extsPtr = StringArrayHelpers.ConvertStringArrayToIntPtrArray(extensions);

            IntPtr csr;
            uint csrLength;

            CKR rv = session.LowLevelPkcs11.C_EX_CreateCSR(session.SessionId, publicKey.ObjectId,
                dnPtr, (uint) dnPtr.Length,
                out csr, out csrLength,
                privateKey.ObjectId,
                null, 0,
                extsPtr, (uint) extsPtr.Length);

            StringArrayHelpers.FreeUnmanagedIntPtrArray(dnPtr);
            StringArrayHelpers.FreeUnmanagedIntPtrArray(extsPtr);

            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_CreateCSR", rv);

            try
            {
                var csrString = PKIHelpers.GetBase64CSR(csr, (int) csrLength);
                if (csrString.Length == 0)
                    throw new InvalidOperationException("C_EX_CreateCSR: invalid csr length");

                return csrString;
            }
            finally
            {
                rv = session.LowLevelPkcs11.C_EX_FreeBuffer(csr);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
            }
        }

        public static string GetCertificateInfoText(this HLA41.Session session, HLA41.ObjectHandle certificate)
        {
            IntPtr certificateInfo;
            uint certificateInfoLen;

            CKR rv = session.LowLevelPkcs11.C_EX_GetCertificateInfoText(
                session.SessionId, certificate.ObjectId, out certificateInfo, out certificateInfoLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetCertificateInfoText", rv);

            if (certificateInfoLen <= 0)
                throw new InvalidOperationException(
                    "C_EX_GetCertificateInfoText: invalid certificate info length");

            byte[] certificateInfoArray = new byte[certificateInfoLen];
            Marshal.Copy(certificateInfo, certificateInfoArray, 0, (int) certificateInfoLen);

            rv = session.LowLevelPkcs11.C_EX_FreeBuffer(certificateInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);

            return ConvertUtils.BytesToUtf8String(certificateInfoArray);
        }

        public static byte[] PKCS7Sign(this HLA41.Session session, byte[] data, HLA41.ObjectHandle certificate,
            HLA41.ObjectHandle privateKey, uint[] certificates, uint flags)
        {
            IntPtr signature;
            uint signatureLen;

            CKR rv = session.LowLevelPkcs11.C_EX_PKCS7Sign(session.SessionId, data, certificate.ObjectId,
                out signature, out signatureLen,
                privateKey.ObjectId,
                certificates, flags);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_PKCS7Sign", rv);

            if (signatureLen <= 0)
                throw new InvalidOperationException("C_EX_PKCS7Sign: invalid signature length");

            byte[] signatureArray = new byte[signatureLen];
            Marshal.Copy(signature, signatureArray, 0, (int) signatureLen);

            rv = session.LowLevelPkcs11.C_EX_FreeBuffer(signature);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);

            return signatureArray;
        }

        public static void TokenManage(this HLA41.Session session, TokenManageMode mode, byte[] value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            IntPtr valuePtr = Marshal.AllocHGlobal(value.Length);
            Marshal.Copy(value, 0, valuePtr, value.Length);

            try
            {
                CKR rv = session.LowLevelPkcs11.C_EX_TokenManage(session.SessionId, (uint)mode, valuePtr);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_TokenManage", rv);
            }
            finally
            {
                Marshal.FreeHGlobal(valuePtr);
            }
        }
    }
}
