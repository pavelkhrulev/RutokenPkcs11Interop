using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.LowLevelAPI81;
using HLA81 = Net.Pkcs11Interop.HighLevelAPI81;

namespace RutokenPkcs11Interop.HighLevelAPI81
{
    public static class SessionExtensions
    {
        public static void UnblockUserPIN(this HLA81.Session session)
        {
            CKR rv = session.LowLevelPkcs11.C_EX_UnblockUserPIN(session.SessionId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_UnblockUserPIN", rv);
        }

        public static void SetTokenName(this HLA81.Session session, string label)
        {
            var labelArray = ConvertUtils.Utf8StringToBytes(label);
            CKR rv = session.LowLevelPkcs11.C_EX_SetTokenName(session.SessionId, labelArray);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetTokenName", rv);
        }

        public static string GetTokenLabel(this HLA81.Session session)
        {
            ulong tokenLabelLength = 0;
            CKR rv = session.LowLevelPkcs11.C_EX_GetTokenName(session.SessionId, null, ref tokenLabelLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetTokenName", rv);

            if (tokenLabelLength <= 0)
                throw new InvalidOperationException(
                    "C_EX_GetTokenName: invalid token label length");

            byte[] tokenLabel = new byte[tokenLabelLength];

            rv = session.LowLevelPkcs11.C_EX_GetTokenName(session.SessionId, tokenLabel, ref tokenLabelLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetTokenName", rv);

            if (tokenLabel.Length != Convert.ToInt32(tokenLabelLength))
                Array.Resize(ref tokenLabel, Convert.ToInt32(tokenLabelLength));

            return ConvertUtils.BytesToUtf8String(tokenLabel);
        }

        public static void SetLicense(this HLA81.Session session, ulong licenseNum, byte[] license)
        {
            if (!Settings.LicenseAllowedNumbers.Contains(Convert.ToUInt32(licenseNum)))
                throw new ArgumentOutOfRangeException(nameof(licenseNum));

            if (license == null)
                throw new ArgumentNullException(nameof(license));

            CKR rv = session.LowLevelPkcs11.C_EX_SetLicense(
                session.SessionId, licenseNum, license);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetLicense", rv);
        }

        public static byte[] GetLicense(this HLA81.Session session, ulong licenseNum)
        {
            if (!Settings.LicenseAllowedNumbers.Contains(Convert.ToUInt32(licenseNum)))
                throw new ArgumentOutOfRangeException(nameof(licenseNum));

            ulong licenseLen = 0;
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

        public static void LoadActivationKey(this HLA81.Session session, byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException(nameof(key));

            CKR rv = session.LowLevelPkcs11.C_EX_LoadActivationKey(
                session.SessionId, key);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_LoadActivationKey", rv);
        }

        public static byte[] GenerateActivationPassword(this HLA81.Session session,
            ActivationPasswordNumber passwordNumber, ActivationPasswordCharacterSet characterSet)
        {
            // Получение длины пароля активации
            ulong passwordLength = 0;
            CKR rv = session.LowLevelPkcs11.C_EX_GenerateActivationPassword(
                session.SessionId, Convert.ToUInt64(passwordNumber), null, ref passwordLength, Convert.ToUInt64(characterSet));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GenerateActivationPassword", rv);

            if (passwordLength <= 0)
                throw new InvalidOperationException(
                    "C_EX_GenerateActivationPassword: invalid password length");

            // Генерация пароля активации
            byte[] password = new byte[passwordLength];
            rv = session.LowLevelPkcs11.C_EX_GenerateActivationPassword(
                session.SessionId, Convert.ToUInt64(passwordNumber), password, ref passwordLength, Convert.ToUInt64(characterSet));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GenerateActivationPassword", rv);

            return password;
        }

        public static byte[] SignInvisible(this HLA81.Session session,
            ref HLA81.Mechanism mechanism, HLA81.ObjectHandle keyHandle, byte[] data)
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

            ulong signatureLen = 0;
            rv = session.LowLevelPkcs11.C_EX_SignInvisible(session.SessionId, data, Convert.ToUInt64(data.Length), null,
                ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisible", rv);

            if (signatureLen <= 0)
                throw new InvalidOperationException(
                    "C_EX_SignInvisible: invalid signature length");

            byte[] signature = new byte[signatureLen];
            rv = session.LowLevelPkcs11.C_EX_SignInvisible(session.SessionId, data, Convert.ToUInt64(data.Length),
                signature, ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SignInvisible", rv);

            if (signature.Length != Convert.ToInt32(signatureLen))
                Array.Resize(ref signature, Convert.ToInt32(signatureLen));

            return signature;
        }

        public static string CreateCSR(this HLA81.Session session, HLA81.ObjectHandle publicKey,
            string[] dn, HLA81.ObjectHandle privateKey, string[] attributes, string[] extensions)
        {
            IntPtr[] dnPtr = StringArrayHelpers.ConvertStringArrayToIntPtrArray(dn);
            IntPtr[] extsPtr = StringArrayHelpers.ConvertStringArrayToIntPtrArray(extensions);

            IntPtr csr;
            ulong csrLength;

            CKR rv = session.LowLevelPkcs11.C_EX_CreateCSR(session.SessionId, publicKey.ObjectId,
                dnPtr, (ulong) dnPtr.Length,
                out csr, out csrLength,
                privateKey.ObjectId,
                null, 0,
                extsPtr, (ulong) extsPtr.Length);

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

        public static string GetCertificateInfoText(this HLA81.Session session, HLA81.ObjectHandle certificate)
        {
            IntPtr certificateInfo;
            ulong certificateInfoLen;

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

        public static byte[] PKCS7Sign(this HLA81.Session session, byte[] data, HLA81.ObjectHandle certificate,
            HLA81.ObjectHandle privateKey, ulong[] certificates, ulong flags)
        {
            IntPtr signature;
            ulong signatureLen;

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

        public static void TokenManage(this HLA81.Session session, TokenManageMode mode, byte[] value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            IntPtr valuePtr = Marshal.AllocHGlobal(value.Length);
            Marshal.Copy(value, 0, valuePtr, value.Length);

            try
            {
                CKR rv = session.LowLevelPkcs11.C_EX_TokenManage(session.SessionId, Convert.ToUInt64(mode), valuePtr);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_TokenManage", rv);
            }
            finally
            {
                Marshal.FreeHGlobal(valuePtr);
            }
        }

        public static byte[] ExtendedWrapKey(this HLA81.Session session,
            HLA81.Mechanism generationMechanism, List<HLA81.ObjectAttribute> keyAttributes,
            HLA81.Mechanism derivationMechanism, HLA81.ObjectHandle baseKey,
            HLA81.Mechanism wrappingMechanism, ref HLA81.ObjectHandle key)
        {
            if (generationMechanism == null)
                throw new ArgumentNullException(nameof(generationMechanism));

            if (derivationMechanism == null)
                throw new ArgumentNullException(nameof(derivationMechanism));

            if (keyAttributes == null)
                throw new ArgumentNullException(nameof(keyAttributes));

            if (baseKey == null)
                throw new ArgumentNullException(nameof(baseKey));

            if (wrappingMechanism == null)
                throw new ArgumentNullException(nameof(wrappingMechanism));

            var ckGenerationMechanism = new CK_MECHANISM()
            {
                Mechanism = generationMechanism.Type
            };

            var ckDerivationMechanism = new CK_MECHANISM()
            {
                Mechanism = derivationMechanism.Type
            };
            var ckWrappingMechanism = new CK_MECHANISM()
            {
                Mechanism = wrappingMechanism.Type
            };

            // Преобразование ObjectAttributes в CK_ATTRIBUTES
            CK_ATTRIBUTE[] ckKeyAttributes = null;
            ulong ckKeyAttributesLen = 0;
            ckKeyAttributes = new CK_ATTRIBUTE[keyAttributes.Count];
            for (int i = 0; i < keyAttributes.Count; i++)
            {
                ckKeyAttributes[i] = keyAttributes[i].GetPrivatePropertyValue<CK_ATTRIBUTE>("CkAttribute");
            }
            ckKeyAttributesLen = Convert.ToUInt64(keyAttributes.Count);

            // Получение длины wrapped key
            ulong generatedKey = CK.CK_INVALID_HANDLE;
            ulong wrappedKeyLen = 0;
            CKR rv = session.LowLevelPkcs11.C_EX_WrapKey(session.SessionId, ref ckGenerationMechanism, ckKeyAttributes,
                ckKeyAttributesLen,
                ref ckDerivationMechanism, baseKey.ObjectId, ref ckWrappingMechanism, null, ref wrappedKeyLen,
                ref generatedKey);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_WrapKey", rv);

            if (wrappedKeyLen <= 0)
                throw new InvalidOperationException(
                    "C_EX_WrapKey: invalid wrapped key length");

            // Маскирование ключа
            byte[] wrappedKey = new byte[wrappedKeyLen];
            rv = session.LowLevelPkcs11.C_EX_WrapKey(session.SessionId, ref ckGenerationMechanism, ckKeyAttributes,
                ckKeyAttributesLen,
                ref ckDerivationMechanism, baseKey.ObjectId, ref ckWrappingMechanism, wrappedKey, ref wrappedKeyLen,
                ref generatedKey);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_WrapKey", rv);

            if (generatedKey == CK.CK_INVALID_HANDLE)
                throw new InvalidOperationException("C_EX_WrapKey: invalid generated key handle");

            if (wrappedKey.Length != Convert.ToInt32(wrappedKeyLen))
                Array.Resize(ref wrappedKey, Convert.ToInt32(wrappedKeyLen));

            key = new HLA81.ObjectHandle(generatedKey);

            return wrappedKey;
        }

        public static HLA81.ObjectHandle ExtendedUnwrapKey(this HLA81.Session session,
            HLA81.Mechanism derivationMechanism, HLA81.ObjectHandle baseKey,
            HLA81.Mechanism unwrappingMechanism,
            byte[] wrappedKey, List<HLA81.ObjectAttribute> keyAttributes)
        {
            if (derivationMechanism == null)
                throw new ArgumentNullException(nameof(derivationMechanism));

            if (baseKey == null)
                throw new ArgumentNullException(nameof(baseKey));

            if (unwrappingMechanism == null)
                throw new ArgumentNullException(nameof(unwrappingMechanism));

            if (wrappedKey == null)
                throw new ArgumentNullException(nameof(wrappedKey));

            if (keyAttributes == null)
                throw new ArgumentNullException(nameof(keyAttributes));

            var ckDerivationMechanism = new CK_MECHANISM()
            {
                Mechanism = derivationMechanism.Type
            };
            var ckUnwrappingMechanism = new CK_MECHANISM()
            {
                Mechanism = unwrappingMechanism.Type
            };

            // Преобразование ObjectAttributes в CK_ATTRIBUTES
            CK_ATTRIBUTE[] ckKeyAttributes = null;
            ulong ckKeyAttributesLen = 0;
            ckKeyAttributes = new CK_ATTRIBUTE[keyAttributes.Count];
            for (int i = 0; i < keyAttributes.Count; i++)
            {
                ckKeyAttributes[i] = keyAttributes[i].GetPrivatePropertyValue<CK_ATTRIBUTE>("CkAttribute");
            }
            ckKeyAttributesLen = Convert.ToUInt64(keyAttributes.Count);

            // Размаскирование ключа
            ulong unwrappedKey = CK.CK_INVALID_HANDLE;
            CKR rv = session.LowLevelPkcs11.C_EX_UnwrapKey(session.SessionId,
                ref ckDerivationMechanism, baseKey.ObjectId,
                ref ckUnwrappingMechanism, wrappedKey, Convert.ToUInt64(wrappedKey.Length),
                ckKeyAttributes, ckKeyAttributesLen,
                ref unwrappedKey);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_WrapKey", rv);

            if (unwrappedKey == CK.CK_INVALID_HANDLE)
                throw new InvalidOperationException("C_EX_WrapKey: invalid unwrapped key handle");

            return new HLA81.ObjectHandle(unwrappedKey);
        }
    }
}
