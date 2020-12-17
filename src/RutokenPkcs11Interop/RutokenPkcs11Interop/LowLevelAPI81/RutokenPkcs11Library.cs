using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI81
{
    public class RutokenPkcs11Library: Pkcs11Library
    {
        private RutokenDelegates _rutokenDelegates = null;

        /// <summary>
        /// Loads PCKS#11 library
        /// </summary>
        /// <param name="libraryPath">Library name or path</param>
        public RutokenPkcs11Library(string libraryPath)
            : base(libraryPath)
        {
            try
            {
                _rutokenDelegates = new RutokenDelegates(_libraryHandle);
            }
            catch
            {
                base.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Loads PCKS#11 library
        /// </summary>
        /// <param name="libraryPath">Library name or path</param>
        /// <param name="useGetFunctionList">Flag indicating whether cryptoki function pointers should be acquired via C_GetFunctionList (true) or via platform native function (false)</param>
        public RutokenPkcs11Library(string libraryPath, bool useGetFunctionList)
            : base(libraryPath, useGetFunctionList)
        {
            try
            {
                _rutokenDelegates = new RutokenDelegates(_libraryHandle);
            }
            catch
            {
                base.Dispose();
                throw;
            }
        }

        public CKR C_EX_GetTokenInfoExtended(ulong slotId, ref CK_TOKEN_INFO_EXTENDED info)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GetTokenInfoExtended(slotId, ref info);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_InitToken(ulong slotId, byte[] pin, ref CK_RUTOKEN_INIT_PARAM initInfo)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            ulong rv = _rutokenDelegates.C_EX_InitToken(slotId, pin, pinLength, ref initInfo);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_UnblockUserPIN(ulong session)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_UnblockUserPIN(session);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_SetTokenName(ulong session, byte[] label)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong labelLength = 0;
            if (label != null)
                labelLength = Convert.ToUInt32(label.Length);

            ulong rv = _rutokenDelegates.C_EX_SetTokenName(session, label, labelLength);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_GetTokenName(ulong session, byte[] label, ref ulong labelLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GetTokenName(session, label, ref labelLen);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_GetJournal(ulong slotId, byte[] journal, ref ulong journalLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GetJournal(slotId, journal, ref journalLen);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_SignInvisibleInit(ulong session, ref CK_MECHANISM mechanism, ulong key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_SignInvisibleInit(session, ref mechanism, key);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_SignInvisible(ulong session, byte[] data, ulong dataLen, byte[] signature, ref ulong signatureLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_SignInvisible(
                session, data, dataLen, signature, ref signatureLen);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_SetLocalPIN(ulong slotId, byte[] userPin,
            byte[] newLocalPin, ulong localPinId)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong userPinLength = 0;
            if (userPin != null)
                userPinLength = Convert.ToUInt32(userPin.Length);

            ulong newLocalPinLength = 0;
            if (newLocalPin != null)
                newLocalPinLength = Convert.ToUInt32(newLocalPin.Length);

            ulong rv = _rutokenDelegates.C_EX_SetLocalPIN(slotId, userPin, userPinLength,
                newLocalPin, newLocalPinLength, localPinId);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_GetDriveSize(ulong slotId, ref ulong driveSize)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GetDriveSize(slotId, ref driveSize);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_FormatDrive(ulong slotId, ulong userType,
            byte[] pin, CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            ulong initParamsLength = 0;
            if (initParams != null)
                initParamsLength = Convert.ToUInt32(initParams.Length);

            ulong rv = _rutokenDelegates.C_EX_FormatDrive(slotId, userType, pin, pinLength,
                initParams, initParamsLength);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_GetVolumesInfo(ulong slotId,
            CK_VOLUME_INFO_EXTENDED[] volumesInfo, ref ulong volumesInfoCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GetVolumesInfo(slotId, volumesInfo, ref volumesInfoCount);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_ChangeVolumeAttributes(ulong slotId, ulong userType,
            byte[] pin, ulong volumeId, FlashAccessMode newAccessMode, bool permanent)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            ulong rv = _rutokenDelegates.C_EX_ChangeVolumeAttributes(slotId, userType,
                pin, pinLength,
                volumeId, (ulong)newAccessMode, permanent);
            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_SetLicense(ulong session,
            ulong licenseNum, byte[] license)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong licenseLength = 0;
            if (license != null)
                licenseLength = Convert.ToUInt32(license.Length);

            ulong rv = _rutokenDelegates.C_EX_SetLicense(session, licenseNum, license, licenseLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_GetLicense(ulong session,
            ulong licenseNum, byte[] license, ref ulong licenseLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GetLicense(session, licenseNum, license, ref licenseLen);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_GenerateActivationPassword(ulong session, ulong passwordNumber,
            byte[] password, ref ulong passwordSize, ulong passwordCharacterSet)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GenerateActivationPassword(
                session, passwordNumber, password, ref passwordSize, passwordCharacterSet);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_LoadActivationKey(ulong session, byte[] key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong keyLength = 0;
            if (key != null)
                keyLength = Convert.ToUInt32(key.Length);

            ulong rv = _rutokenDelegates.C_EX_LoadActivationKey(session, key, keyLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_SetActivationPassword(ulong slotId, byte[] password)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_SetActivationPassword(slotId, password);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_CreateCSR(ulong session,
                ulong publicKey,
                IntPtr[] dn, ulong dnLength,
                out IntPtr csr, out ulong csrLength,
                ulong privateKey,
                IntPtr[] attributes, ulong attributesLength,
                IntPtr[] extensions, ulong extensionsLength)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_CreateCSR(session, publicKey, dn, dnLength, out csr, out csrLength, privateKey, attributes,
                attributesLength, extensions, extensionsLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_GetCertificateInfoText(ulong session,
                ulong cert, out IntPtr info, out ulong infoLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_GetCertificateInfoText(session, cert, out info, out infoLen);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_PKCS7Sign(ulong session,
            byte[] data, ulong cert,
            out IntPtr envelope, out ulong encelopeLen,
            ulong privateKey,
            ulong[] certificates,
            ulong flags)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong dataLength = 0;
            if (data != null)
                dataLength = Convert.ToUInt32(data.Length);

            ulong certificatesLength = 0;
            if (certificates != null)
                certificatesLength = Convert.ToUInt32(certificates.Length);

            ulong rv = _rutokenDelegates.C_EX_PKCS7Sign(session, data, dataLength,
                cert, out envelope, out encelopeLen,
                privateKey,
                certificates, certificatesLength,
                flags);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_PKCS7VerifyInit(ulong session,
            byte[] cms,
            ref CK_VENDOR_X509_STORE store, uint mode,
            ulong flags)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong cmsLength = 0;
            if (cms != null)
                cmsLength = Convert.ToUInt64(cms.Length);

            ulong rv = _rutokenDelegates.C_EX_PKCS7VerifyInit(session, cms, cmsLength, ref store, mode, flags);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_PKCS7Verify(ulong session,
            out IntPtr data, out ulong dataSize,
            out IntPtr signerCertificates, out ulong signerCertificatesCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            var rv = _rutokenDelegates.C_EX_PKCS7Verify(session, out data, out dataSize, out signerCertificates, out signerCertificatesCount);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_PKCS7VerifyUpdate(ulong session, byte[] data)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong dataLength = 0;
            if (data != null)
                dataLength = Convert.ToUInt64(data.Length);

            var rv = _rutokenDelegates.C_EX_PKCS7VerifyUpdate(session, data, dataLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_PKCS7VerifyFinal(ulong session,
            out IntPtr signerCertificates, out ulong signerCertificatesCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            var rv = _rutokenDelegates.C_EX_PKCS7VerifyFinal(session, out signerCertificates, out signerCertificatesCount);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_FreeBuffer(IntPtr buffer)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_FreeBuffer(buffer);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_TokenManage(ulong session, ulong mode, IntPtr value)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_TokenManage(session, mode, value);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_SlotManage(ulong slotId, ulong mode, IntPtr value)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_SlotManage(slotId, mode, value);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_WrapKey(ulong session,
            ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            ulong baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref ulong wrappedKeyLen, ref ulong key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_WrapKey(session,
                ref generationMechanism,
                keyTemplate, keyAttributeCount,
                ref derivationMechanism,
                baseKey,
                ref wrappingMechanism,
                wrappedKey, ref wrappedKeyLen, ref key);

            return (CKR)Convert.ToUInt32(rv);
        }

        public CKR C_EX_UnwrapKey(ulong session,
            ref CK_MECHANISM derivationMechanism,
            ulong baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, ulong wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref ulong key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            ulong rv = _rutokenDelegates.C_EX_UnwrapKey(session,
                ref derivationMechanism,
                baseKey, ref unwrappingMechanism,
                wrappedKey, wrappedKeyLen,
                keyTemplate, keyAttributeCount,
                ref key);

            return (CKR)Convert.ToUInt32(rv);
        }

    }
}
