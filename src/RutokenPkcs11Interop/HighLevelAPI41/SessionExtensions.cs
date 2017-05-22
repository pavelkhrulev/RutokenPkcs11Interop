using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
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

            CKR rv = session.LowLevelPkcs11.C_EX_SignInvisibleInit(session.SessionId, ref ckMechanism, keyHandle.ObjectId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisibleInit", rv);

            uint signatureLen = 0;
            rv = session.LowLevelPkcs11.C_EX_SignInvisible(session.SessionId, data, Convert.ToUInt32(data.Length), null, ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisible", rv);

            byte[] signature = new byte[signatureLen];
            rv = session.LowLevelPkcs11.C_EX_SignInvisible(session.SessionId, data, Convert.ToUInt32(data.Length), signature, ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisible", rv);

            if (signature.Length != signatureLen)
                Array.Resize(ref signature, Convert.ToInt32(signatureLen));

            return signature;
        }
    }
}
