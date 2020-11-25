using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.HighLevelAPI;
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

        public static Pkcs7VerificationResult PKCS7Verify(this HLA81.Session session, byte[] cms, CkVendorX509Store vendorX509Store,
            VendorCrlMode mode, ulong flags)
        {
            if (session.Disposed)
                throw new ObjectDisposedException(session.GetType().FullName);

            if (cms == null)
                throw new ArgumentNullException(nameof(cms));

            if (vendorX509Store == null)
                throw new ArgumentNullException(nameof(vendorX509Store));

            var storeNative = new CK_VENDOR_X509_STORE(vendorX509Store);

            var data = IntPtr.Zero;
            ulong dataLen = 0;

            var initialSignerSertificates = IntPtr.Zero;
            var signerSertificates = IntPtr.Zero;
            ulong signerSertificatesCount = 0;

            try
            {
                CKR rv = session.LowLevelPkcs11.C_EX_PKCS7VerifyInit(session.SessionId, cms, ref storeNative, Convert.ToUInt32(mode), flags);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_PKCS7VerifyInit", rv);

                rv = session.LowLevelPkcs11.C_EX_PKCS7Verify(session.SessionId, out data, out dataLen, out signerSertificates, out signerSertificatesCount);

                var result = new Pkcs7VerificationResult();

                if (rv == CKR.CKR_OK)
                {
                    result.Data = new byte[dataLen];
                    Marshal.Copy(data, result.Data, 0, (int)dataLen);

                    result.Certificates = new List<byte[]>();
                    var structSize = Marshal.SizeOf(typeof(CK_VENDOR_BUFFER));
                    initialSignerSertificates = signerSertificates;

                    for (var i = 0; i < (int)signerSertificatesCount; i++)
                    {
                        var certificatePtr = (CK_VENDOR_BUFFER)Marshal.PtrToStructure(signerSertificates, typeof(CK_VENDOR_BUFFER));
                        signerSertificates += structSize;

                        var certificateData = new byte[certificatePtr.Size];
                        Marshal.Copy(certificatePtr.Data, certificateData, 0, (int)certificatePtr.Size);

                        result.Certificates.Add(certificateData);
                    }

                    result.IsValid = true;
                }
                else if (rv == CKR.CKR_SIGNATURE_INVALID)
                {
                    result.IsValid = false;
                }
                else
                {
                    throw new Pkcs11Exception("C_EX_PKCS7Verify", rv);
                }

                return result;
            }
            finally
            {
                storeNative.Dispose();

                if (initialSignerSertificates != IntPtr.Zero)
                {
                    var structSize = Marshal.SizeOf(typeof(CK_VENDOR_BUFFER));

                    for (ulong i = 0; i < signerSertificatesCount; i++)
                    {
                        var certificatePtr = (CK_VENDOR_BUFFER)Marshal.PtrToStructure(initialSignerSertificates, typeof(CK_VENDOR_BUFFER));
                        initialSignerSertificates += structSize;

                        CKR rv = session.LowLevelPkcs11.C_EX_FreeBuffer(certificatePtr.Data);
                        if (rv != CKR.CKR_OK)
                            throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
                    }
                }

                if (data != IntPtr.Zero)
                {
                    CKR rv = session.LowLevelPkcs11.C_EX_FreeBuffer(data);
                    if (rv != CKR.CKR_OK)
                        throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
                }
            }
        }

        public static Pkcs7VerificationResult PKCS7Verify(this HLA81.Session session, byte[] cms, Stream inputStream, CkVendorX509Store vendorX509Store,
            VendorCrlMode mode, ulong flags)
        {
            if (session.Disposed)
                throw new ObjectDisposedException(session.GetType().FullName);

            if (cms == null)
                throw new ArgumentNullException(nameof(cms));

            if (vendorX509Store == null)
                throw new ArgumentNullException(nameof(vendorX509Store));

            var storeNative = new CK_VENDOR_X509_STORE(vendorX509Store);

            var initialSignerSertificates = IntPtr.Zero;
            var signerSertificates = IntPtr.Zero;
            ulong signerSertificatesCount = 0;

            try
            {
                CKR rv = session.LowLevelPkcs11.C_EX_PKCS7VerifyInit(session.SessionId, cms, ref storeNative, Convert.ToUInt32(mode), flags);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_PKCS7VerifyInit", rv);

                byte[] part = new byte[inputStream.Length];

                while (inputStream.Read(part, 0, part.Length) > 0)
                {
                    rv = session.LowLevelPkcs11.C_EX_PKCS7VerifyUpdate(session.SessionId, part);
                    if (rv != CKR.CKR_OK)
                        throw new Pkcs11Exception("C_EX_PKCS7VerifyUpdate", rv);
                }

                rv = session.LowLevelPkcs11.C_EX_PKCS7VerifyFinal(session.SessionId, out signerSertificates, out signerSertificatesCount);

                var result = new Pkcs7VerificationResult();

                if (rv == CKR.CKR_OK)
                {
                    result.Certificates = new List<byte[]>();
                    var structSize = Marshal.SizeOf(typeof(CK_VENDOR_BUFFER));
                    initialSignerSertificates = signerSertificates;

                    for (var i = 0; i < (int)signerSertificatesCount; i++)
                    {
                        var certificatePtr = (CK_VENDOR_BUFFER)Marshal.PtrToStructure(signerSertificates, typeof(CK_VENDOR_BUFFER));
                        signerSertificates += structSize;

                        var certificateData = new byte[certificatePtr.Size];
                        Marshal.Copy(certificatePtr.Data, certificateData, 0, (int)certificatePtr.Size);

                        result.Certificates.Add(certificateData);
                    }

                    result.IsValid = true;
                }
                else if (rv == CKR.CKR_SIGNATURE_INVALID)
                {
                    result.IsValid = false;
                }
                else
                {
                    throw new Pkcs11Exception("C_EX_PKCS7VerifyFinal", rv);
                }

                return result;
            }
            finally
            {
                storeNative.Dispose();

                if (initialSignerSertificates != IntPtr.Zero)
                {
                    var structSize = Marshal.SizeOf(typeof(CK_VENDOR_BUFFER));

                    for (ulong i = 0; i < signerSertificatesCount; i++)
                    {
                        var certificatePtr = (CK_VENDOR_BUFFER)Marshal.PtrToStructure(initialSignerSertificates, typeof(CK_VENDOR_BUFFER));
                        initialSignerSertificates += structSize;

                        CKR rv = session.LowLevelPkcs11.C_EX_FreeBuffer(certificatePtr.Data);
                        if (rv != CKR.CKR_OK)
                            throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
                    }
                }
            }
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

        public static HLA81.ObjectHandle GetPinPolicyObject(this HLA81.Session session, CKU userType)
        {
            CKR rv;
            CK_ATTRIBUTE[] pinPolicyTemplate = new CK_ATTRIBUTE[3];

            pinPolicyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_HW_FEATURE);
            pinPolicyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_HW_FEATURE_TYPE, (ulong)Extended_CKH.CKH_VENDOR_PIN_POLICY);
            pinPolicyTemplate[2] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_USER_TYPE, (ulong)userType);

            ulong foundObjectCount = 0;
            ulong[] foundObjectIds = new ulong[1];

            rv = session.LowLevelPkcs11.C_FindObjectsInit(session.SessionId, pinPolicyTemplate, Convert.ToUInt64(pinPolicyTemplate.Length));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_FindObjectsInit", rv);

            rv = session.LowLevelPkcs11.C_FindObjects(session.SessionId, foundObjectIds, Convert.ToUInt64(foundObjectIds.Length), ref foundObjectCount);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_FindObjects", rv);

            rv = session.LowLevelPkcs11.C_FindObjectsFinal(session.SessionId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_FindObjectsFinal", rv);

            if (foundObjectCount != 1)
                throw new Exception("Pin policy object not found");

            return new HLA81.ObjectHandle(foundObjectIds[0]);
        }

        public static bool PinPolicySupports(this HLA81.Session session, CKU userType)
        {
            CKR rv;
            HLA81.ObjectHandle pinPolicyObj = GetPinPolicyObject(session, userType);
            CK_ATTRIBUTE[] pinPolicyTemplate = new CK_ATTRIBUTE[1];
            pinPolicyTemplate[0] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_SUPPORTED_PIN_POLICIES);

            rv = session.LowLevelPkcs11.C_GetAttributeValue(session.SessionId, pinPolicyObj.ObjectId, pinPolicyTemplate, Convert.ToUInt64(pinPolicyTemplate.Length));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetAttributeValue", rv);

            return pinPolicyTemplate[0].valueLen != 0;
        }

        public static PinPolicy GetPinPolicy(this HLA81.Session session, CKU userType)
        {
            CKR rv;
            PinPolicy pinPolicy = new PinPolicy();
            HLA81.ObjectHandle pinPolicyObj = GetPinPolicyObject(session, userType);

            CK_ATTRIBUTE[] pinPolicyTemplate = new CK_ATTRIBUTE[10];
            pinPolicyTemplate[0] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_MIN_LENGTH, new byte[1]);
            pinPolicyTemplate[1] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_HISTORY_DEPTH, new byte[1]);
            pinPolicyTemplate[2] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_ALLOW_DEFAULT_PIN_USAGE, new byte[1]);
            pinPolicyTemplate[3] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_DIGIT_REQUIRED, new byte[1]);
            pinPolicyTemplate[4] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_UPPERCASE_REQUIRED, new byte[1]);
            pinPolicyTemplate[5] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_LOWERCASE_REQUIRED, new byte[1]);
            pinPolicyTemplate[6] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_SPEC_CHAR_REQUIRED, new byte[1]);
            pinPolicyTemplate[7] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_DIFF_CHARS_REQUIRED, new byte[1]);
            pinPolicyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, new bool());
            pinPolicyTemplate[9] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICIES_DELETABLE, new bool());

            rv = session.LowLevelPkcs11.C_GetAttributeValue(session.SessionId, pinPolicyObj.ObjectId, pinPolicyTemplate, Convert.ToUInt64(pinPolicyTemplate.Length));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetAttributeValue", rv);

            byte[] minPolicyLength;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[0], out minPolicyLength);
            pinPolicy.MinPinLength = minPolicyLength[0];

            byte[] pinHistoryDepth;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[1], out pinHistoryDepth);
            pinPolicy.PinHistoryDepth = pinHistoryDepth[0];

            byte[] allowDefaultPinUsage;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[2], out allowDefaultPinUsage);
            pinPolicy.AllowDefaultPinUsage = allowDefaultPinUsage[0] != 0;

            byte[] pinContainsDigit;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[3], out pinContainsDigit);
            pinPolicy.PinContainsDigit = pinContainsDigit[0] != 0;

            byte[] pinContainsUpperLetter;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[4], out pinContainsUpperLetter);
            pinPolicy.PinContainsUpperLetter = pinContainsUpperLetter[0] != 0;

            byte[] pinContainsLowerLetter;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[5], out pinContainsLowerLetter);
            pinPolicy.PinContainsLowerLetter = pinContainsLowerLetter[0] != 0;

            byte[] pinContainsSpecChar;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[6], out pinContainsSpecChar);
            pinPolicy.PinContainsSpecChar = pinContainsSpecChar[0] != 0;

            byte[] restrictOneCharPin;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[7], out restrictOneCharPin);
            pinPolicy.RestrictOneCharPin = restrictOneCharPin[0] != 0;

            bool allowChangePinPolicy;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[8], out allowChangePinPolicy);
            pinPolicy.AllowChangePinPolicy = allowChangePinPolicy;

            bool removePinPolicyAfterFormat;
            CkaUtils.ConvertValue(ref pinPolicyTemplate[9], out removePinPolicyAfterFormat);
            pinPolicy.RemovePinPolicyAfterFormat = removePinPolicyAfterFormat;

            return pinPolicy;
        }

        public static void SetPinPolicy(this HLA81.Session session, PinPolicy pinPolicy, CKU userType)
        {
            CKR rv;
            HLA81.ObjectHandle pinPolicyObj = GetPinPolicyObject(session, userType);


            CK_ATTRIBUTE[] pinPolicyTemplate = new CK_ATTRIBUTE[10];
            pinPolicyTemplate[0] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_MIN_LENGTH, new byte[] { Convert.ToByte(pinPolicy.MinPinLength) });
            pinPolicyTemplate[1] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_HISTORY_DEPTH, new byte[] { Convert.ToByte(pinPolicy.PinHistoryDepth) });
            pinPolicyTemplate[2] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_ALLOW_DEFAULT_PIN_USAGE, new byte[] { Convert.ToByte(pinPolicy.AllowDefaultPinUsage) });
            pinPolicyTemplate[3] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_DIGIT_REQUIRED, new byte[] { Convert.ToByte(pinPolicy.PinContainsDigit) });
            pinPolicyTemplate[4] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_UPPERCASE_REQUIRED, new byte[] { Convert.ToByte(pinPolicy.PinContainsUpperLetter) });
            pinPolicyTemplate[5] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_LOWERCASE_REQUIRED, new byte[] { Convert.ToByte(pinPolicy.PinContainsLowerLetter) });
            pinPolicyTemplate[6] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_SPEC_CHAR_REQUIRED, new byte[] { Convert.ToByte(pinPolicy.PinContainsSpecChar) });
            pinPolicyTemplate[7] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICY_DIFF_CHARS_REQUIRED, new byte[] { Convert.ToByte(pinPolicy.RestrictOneCharPin) });
            pinPolicyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, Convert.ToBoolean(pinPolicy.AllowChangePinPolicy));
            pinPolicyTemplate[9] = CkaUtils.CreateAttribute((CKA)Extended_CKA.CKA_VENDOR_PIN_POLICIES_DELETABLE, Convert.ToBoolean(pinPolicy.RemovePinPolicyAfterFormat));

            rv = session.LowLevelPkcs11.C_SetAttributeValue(session.SessionId, pinPolicyObj.ObjectId, pinPolicyTemplate, Convert.ToUInt64(pinPolicyTemplate.Length));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_GetAttributeValue", rv);
        }
    }
}
