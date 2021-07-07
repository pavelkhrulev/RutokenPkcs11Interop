using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI80;
using Net.RutokenPkcs11Interop.Common;

using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI80
{
    public class RutokenPkcs11Library: Pkcs11Library
    {
        /// <summary>
        /// Delegates for vendor specific unmanaged functions
        /// </summary>
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

        public CKR C_EX_GetTokenInfoExtended(NativeULong slotId, ref CK_TOKEN_INFO_EXTENDED info)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GetTokenInfoExtended(slotId, ref info);
            return (CKR)rv;
        }

        public CKR C_EX_InitToken(NativeULong slotId, byte[] pin, ref CK_RUTOKEN_INIT_PARAM initInfo)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong pinLength = 0;
            if (pin != null)
                pinLength = (NativeULong)(pin.Length);

            NativeULong rv = _rutokenDelegates.C_EX_InitToken(slotId, pin, pinLength, ref initInfo);
            return (CKR)rv;
        }

        public CKR C_EX_UnblockUserPIN(NativeULong session)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_UnblockUserPIN(session);
            return (CKR)rv;
        }

        public CKR C_EX_SetTokenName(NativeULong session, byte[] label)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong labelLength = 0;
            if (label != null)
                labelLength = (NativeULong)(label.Length);

            NativeULong rv = _rutokenDelegates.C_EX_SetTokenName(session, label, labelLength);
            return (CKR)rv;
        }

        public CKR C_EX_GetTokenName(NativeULong session, byte[] label, ref NativeULong labelLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GetTokenName(session, label, ref labelLen);
            return (CKR)rv;
        }

        public CKR C_EX_GetJournal(NativeULong slotId, byte[] journal, ref NativeULong journalLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GetJournal(slotId, journal, ref journalLen);
            return (CKR)rv;
        }

        public CKR C_EX_SignInvisibleInit(NativeULong session, ref CK_MECHANISM mechanism, NativeULong key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_SignInvisibleInit(session, ref mechanism, key);
            return (CKR)rv;
        }

        public CKR C_EX_SignInvisible(NativeULong session, byte[] data, NativeULong dataLen, byte[] signature, ref NativeULong signatureLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_SignInvisible(
                session, data, dataLen, signature, ref signatureLen);
            return (CKR)rv;
        }

        public CKR C_EX_SetLocalPIN(NativeULong slotId, byte[] userPin,
            byte[] newLocalPin, NativeULong localPinId)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong userPinLength = 0;
            if (userPin != null)
                userPinLength = (NativeULong)(userPin.Length);

            NativeULong newLocalPinLength = 0;
            if (newLocalPin != null)
                newLocalPinLength = (NativeULong)(newLocalPin.Length);

            NativeULong rv = _rutokenDelegates.C_EX_SetLocalPIN(slotId, userPin, userPinLength,
                newLocalPin, newLocalPinLength, localPinId);
            return (CKR)rv;
        }

        public CKR C_EX_GetDriveSize(NativeULong slotId, ref NativeULong driveSize)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GetDriveSize(slotId, ref driveSize);
            return (CKR)rv;
        }

        public CKR C_EX_FormatDrive(NativeULong slotId, NativeULong userType,
            byte[] pin, CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong pinLength = 0;
            if (pin != null)
                pinLength = (NativeULong)(pin.Length);

            NativeULong initParamsLength = 0;
            if (initParams != null)
                initParamsLength = (NativeULong)(initParams.Length);

            NativeULong rv = _rutokenDelegates.C_EX_FormatDrive(slotId, userType, pin, pinLength,
                initParams, initParamsLength);
            return (CKR)rv;
        }

        public CKR C_EX_GetVolumesInfo(NativeULong slotId,
            CK_VOLUME_INFO_EXTENDED[] volumesInfo, ref NativeULong volumesInfoCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GetVolumesInfo(slotId, volumesInfo, ref volumesInfoCount);
            return (CKR)rv;
        }

        public CKR C_EX_ChangeVolumeAttributes(NativeULong slotId, NativeULong userType,
            byte[] pin, NativeULong volumeId, FlashAccessMode newAccessMode, bool permanent)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong pinLength = 0;
            if (pin != null)
                pinLength = (NativeULong)(pin.Length);

            NativeULong rv = _rutokenDelegates.C_EX_ChangeVolumeAttributes(slotId, userType,
                pin, pinLength,
                volumeId, (NativeULong)newAccessMode, permanent);
            return (CKR)rv;
        }

        public CKR C_EX_SetLicense(NativeULong session,
            NativeULong licenseNum, byte[] license)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong licenseLength = 0;
            if (license != null)
                licenseLength = (NativeULong)(license.Length);

            NativeULong rv = _rutokenDelegates.C_EX_SetLicense(session, licenseNum, license, licenseLength);

            return (CKR)rv;
        }

        public CKR C_EX_GetLicense(NativeULong session,
            NativeULong licenseNum, byte[] license, ref NativeULong licenseLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GetLicense(session, licenseNum, license, ref licenseLen);

            return (CKR)rv;
        }

        public CKR C_EX_GenerateActivationPassword(NativeULong session, NativeULong passwordNumber,
            byte[] password, ref NativeULong passwordSize, NativeULong passwordCharacterSet)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GenerateActivationPassword(
                session, passwordNumber, password, ref passwordSize, passwordCharacterSet);

            return (CKR)rv;
        }

        public CKR C_EX_LoadActivationKey(NativeULong session, byte[] key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong keyLength = 0;
            if (key != null)
                keyLength = (NativeULong)(key.Length);

            NativeULong rv = _rutokenDelegates.C_EX_LoadActivationKey(session, key, keyLength);

            return (CKR)rv;
        }

        public CKR C_EX_SetActivationPassword(NativeULong slotId, byte[] password)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_SetActivationPassword(slotId, password);

            return (CKR)rv;
        }

        public CKR C_EX_CreateCSR(NativeULong session,
                NativeULong publicKey,
                IntPtr[] dn, NativeULong dnLength,
                out IntPtr csr, out NativeULong csrLength,
                NativeULong privateKey,
                IntPtr[] attributes, NativeULong attributesLength,
                IntPtr[] extensions, NativeULong extensionsLength)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_CreateCSR(session, publicKey, dn, dnLength, out csr, out csrLength, privateKey, attributes,
                attributesLength, extensions, extensionsLength);

            return (CKR)rv;
        }

        public CKR C_EX_GetCertificateInfoText(NativeULong session,
                NativeULong cert, out IntPtr info, out NativeULong infoLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_GetCertificateInfoText(session, cert, out info, out infoLen);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7Sign(NativeULong session,
            byte[] data, NativeULong cert,
            out IntPtr envelope, out NativeULong encelopeLen,
            NativeULong privateKey,
            NativeULong[] certificates,
            NativeULong flags)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong dataLength = 0;
            if (data != null)
                dataLength = (NativeULong)(data.Length);

            NativeULong certificatesLength = 0;
            if (certificates != null)
                certificatesLength = (NativeULong)(certificates.Length);

            NativeULong rv = _rutokenDelegates.C_EX_PKCS7Sign(session, data, dataLength,
                cert, out envelope, out encelopeLen,
                privateKey,
                certificates, certificatesLength,
                flags);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7VerifyInit(NativeULong session,
            byte[] cms,
            ref CK_VENDOR_X509_STORE store, NativeULong mode,
            NativeULong flags)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong cmsLength = 0;
            if (cms != null)
                cmsLength = (NativeULong)(cms.Length);

            NativeULong rv = _rutokenDelegates.C_EX_PKCS7VerifyInit(session, cms, cmsLength, ref store, mode, flags);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7Verify(NativeULong session,
            out IntPtr data, out NativeULong dataSize,
            out IntPtr signerCertificates, out NativeULong signerCertificatesCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_PKCS7Verify(session, out data, out dataSize, out signerCertificates, out signerCertificatesCount);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7VerifyUpdate(NativeULong session, byte[] data)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong dataLength = 0;
            if (data != null)
                dataLength = (NativeULong)(data.Length);

            NativeULong rv = _rutokenDelegates.C_EX_PKCS7VerifyUpdate(session, data, dataLength);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7VerifyFinal(NativeULong session,
            out IntPtr signerCertificates, out NativeULong signerCertificatesCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_PKCS7VerifyFinal(session, out signerCertificates, out signerCertificatesCount);

            return (CKR)rv;
        }

        public CKR C_EX_FreeBuffer(IntPtr buffer)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_FreeBuffer(buffer);

            return (CKR)rv;
        }

        public CKR C_EX_TokenManage(NativeULong session, NativeULong mode, IntPtr value)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_TokenManage(session, mode, value);

            return (CKR)rv;
        }

        public CKR C_EX_SlotManage(NativeULong slotId, NativeULong mode, IntPtr value)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_SlotManage(slotId, mode, value);

            return (CKR)rv;
        }

        public CKR C_EX_WrapKey(NativeULong session,
            ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, NativeULong keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            NativeULong baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref NativeULong wrappedKeyLen, ref NativeULong key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_WrapKey(session,
                ref generationMechanism,
                keyTemplate, keyAttributeCount,
                ref derivationMechanism,
                baseKey,
                ref wrappingMechanism,
                wrappedKey, ref wrappedKeyLen, ref key);

            return (CKR)rv;
        }

        public CKR C_EX_UnwrapKey(NativeULong session,
            ref CK_MECHANISM derivationMechanism,
            NativeULong baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, NativeULong wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, NativeULong keyAttributeCount,
            ref NativeULong key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            NativeULong rv = _rutokenDelegates.C_EX_UnwrapKey(session,
                ref derivationMechanism,
                baseKey, ref unwrappingMechanism,
                wrappedKey, wrappedKeyLen,
                keyTemplate, keyAttributeCount,
                ref key);

            return (CKR)rv;
        }

    }
}
