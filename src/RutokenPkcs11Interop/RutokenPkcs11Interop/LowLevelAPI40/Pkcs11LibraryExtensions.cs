using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI40;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI40
{
    public class Pkcs11LibraryExtensions: Pkcs11Library
    {
        /// <summary>
        /// Delegates for vendor specific unmanaged functions
        /// </summary>
        private RutokenDelegates _rutokenDelegates = null;

        /// <summary>
        /// Loads PCKS#11 library
        /// </summary>
        /// <param name="libraryPath">Library name or path</param>
        public Pkcs11LibraryExtensions(string libraryPath)
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
        public Pkcs11LibraryExtensions(string libraryPath, bool useGetFunctionList)
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

        public CKR C_EX_GetTokenInfoExtended(uint slotId, ref CK_TOKEN_INFO_EXTENDED info)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GetTokenInfoExtended(slotId, ref info);
            return (CKR)rv;
        }

        public CKR C_EX_InitToken(uint slotId, byte[] pin, ref CK_RUTOKEN_INIT_PARAM initInfo)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            uint rv = _rutokenDelegates.C_EX_InitToken(slotId, pin, pinLength, ref initInfo);
            return (CKR)rv;
        }

        public CKR C_EX_UnblockUserPIN(uint session)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_UnblockUserPIN(session);
            return (CKR)rv;
        }

        public CKR C_EX_SetTokenName(uint session, byte[] label)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint labelLength = 0;
            if (label != null)
                labelLength = Convert.ToUInt32(label.Length);

            uint rv = _rutokenDelegates.C_EX_SetTokenName(session, label, labelLength);
            return (CKR)rv;
        }

        public CKR C_EX_GetTokenName(uint session, byte[] label, ref uint labelLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GetTokenName(session, label, ref labelLen);
            return (CKR)rv;
        }

        public CKR C_EX_GetJournal(uint slotId, byte[] journal, ref uint journalLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GetJournal(slotId, journal, ref journalLen);
            return (CKR)rv;
        }

        public CKR C_EX_SignInvisibleInit(uint session, ref CK_MECHANISM mechanism, uint key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_SignInvisibleInit(session, ref mechanism, key);
            return (CKR)rv;
        }

        public CKR C_EX_SignInvisible(uint session, byte[] data, uint dataLen, byte[] signature, ref uint signatureLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_SignInvisible(
                session, data, dataLen, signature, ref signatureLen);
            return (CKR)rv;
        }

        public CKR C_EX_SetLocalPIN(uint slotId, byte[] userPin,
            byte[] newLocalPin, uint localPinId)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint userPinLength = 0;
            if (userPin != null)
                userPinLength = Convert.ToUInt32(userPin.Length);

            uint newLocalPinLength = 0;
            if (newLocalPin != null)
                newLocalPinLength = Convert.ToUInt32(newLocalPin.Length);

            uint rv = _rutokenDelegates.C_EX_SetLocalPIN(slotId, userPin, userPinLength,
                newLocalPin, newLocalPinLength, localPinId);
            return (CKR)rv;
        }

        public CKR C_EX_GetDriveSize(uint slotId, ref uint driveSize)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GetDriveSize(slotId, ref driveSize);
            return (CKR)rv;
        }

        public CKR C_EX_FormatDrive(uint slotId, uint userType,
            byte[] pin, CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            uint initParamsLength = 0;
            if (initParams != null)
                initParamsLength = Convert.ToUInt32(initParams.Length);

            uint rv = _rutokenDelegates.C_EX_FormatDrive(slotId, userType, pin, pinLength,
                initParams, initParamsLength);
            return (CKR)rv;
        }

        public CKR C_EX_GetVolumesInfo(uint slotId,
            CK_VOLUME_INFO_EXTENDED[] volumesInfo, ref uint volumesInfoCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GetVolumesInfo(slotId, volumesInfo, ref volumesInfoCount);
            return (CKR)rv;
        }

        public CKR C_EX_ChangeVolumeAttributes(uint slotId, uint userType,
            byte[] pin, uint volumeId, FlashAccessMode newAccessMode, bool permanent)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            uint rv = _rutokenDelegates.C_EX_ChangeVolumeAttributes(slotId, userType,
                pin, pinLength,
                volumeId, (uint)newAccessMode, permanent);
            return (CKR)rv;
        }

        public CKR C_EX_SetLicense(uint session,
            uint licenseNum, byte[] license)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint licenseLength = 0;
            if (license != null)
                licenseLength = Convert.ToUInt32(license.Length);

            uint rv = _rutokenDelegates.C_EX_SetLicense(session, licenseNum, license, licenseLength);

            return (CKR)rv;
        }

        public CKR C_EX_GetLicense(uint session,
            uint licenseNum, byte[] license, ref uint licenseLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GetLicense(session, licenseNum, license, ref licenseLen);

            return (CKR)rv;
        }

        public CKR C_EX_GenerateActivationPassword(uint session, uint passwordNumber,
            byte[] password, ref uint passwordSize, uint passwordCharacterSet)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GenerateActivationPassword(
                session, passwordNumber, password, ref passwordSize, passwordCharacterSet);

            return (CKR)rv;
        }

        public CKR C_EX_LoadActivationKey(uint session, byte[] key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint keyLength = 0;
            if (key != null)
                keyLength = Convert.ToUInt32(key.Length);

            uint rv = _rutokenDelegates.C_EX_LoadActivationKey(session, key, keyLength);

            return (CKR)rv;
        }

        public CKR C_EX_SetActivationPassword(uint slotId, byte[] password)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_SetActivationPassword(slotId, password);

            return (CKR)rv;
        }

        public CKR C_EX_CreateCSR(uint session,
                uint publicKey,
                IntPtr[] dn, uint dnLength,
                out IntPtr csr, out uint csrLength,
                uint privateKey,
                IntPtr[] attributes, uint attributesLength,
                IntPtr[] extensions, uint extensionsLength)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_CreateCSR(session, publicKey, dn, dnLength, out csr, out csrLength, privateKey, attributes,
                attributesLength, extensions, extensionsLength);

            return (CKR)rv;
        }

        public CKR C_EX_GetCertificateInfoText(uint session,
                uint cert, out IntPtr info, out uint infoLen)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_GetCertificateInfoText(session, cert, out info, out infoLen);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7Sign(uint session,
            byte[] data, uint cert,
            out IntPtr envelope, out uint encelopeLen,
            uint privateKey,
            uint[] certificates,
            uint flags)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint dataLength = 0;
            if (data != null)
                dataLength = Convert.ToUInt32(data.Length);

            uint certificatesLength = 0;
            if (certificates != null)
                certificatesLength = Convert.ToUInt32(certificates.Length);

            uint rv = _rutokenDelegates.C_EX_PKCS7Sign(session, data, dataLength,
                cert, out envelope, out encelopeLen,
                privateKey,
                certificates, certificatesLength,
                flags);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7VerifyInit(uint session,
            byte[] cms,
            ref CK_VENDOR_X509_STORE store, uint mode,
            uint flags)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint cmsLength = 0;
            if (cms != null)
                cmsLength = Convert.ToUInt32(cms.Length);

            uint rv = _rutokenDelegates.C_EX_PKCS7VerifyInit(session, cms, cmsLength, ref store, mode, flags);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7Verify(uint session,
            out IntPtr data, out uint dataSize,
            out IntPtr signerCertificates, out uint signerCertificatesCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_PKCS7Verify(session, out data, out dataSize, out signerCertificates, out signerCertificatesCount);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7VerifyUpdate(uint session, byte[] data)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint dataLength = 0;
            if (data != null)
                dataLength = Convert.ToUInt32(data.Length);

            uint rv = _rutokenDelegates.C_EX_PKCS7VerifyUpdate(session, data, dataLength);

            return (CKR)rv;
        }

        public CKR C_EX_PKCS7VerifyFinal(uint session,
            out IntPtr signerCertificates, out uint signerCertificatesCount)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_PKCS7VerifyFinal(session, out signerCertificates, out signerCertificatesCount);

            return (CKR)rv;
        }

        public CKR C_EX_FreeBuffer(IntPtr buffer)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_FreeBuffer(buffer);

            return (CKR)rv;
        }

        public CKR C_EX_TokenManage(uint session, uint mode, IntPtr value)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_TokenManage(session, mode, value);

            return (CKR)rv;
        }

        public CKR C_EX_SlotManage(uint slotId, uint mode, IntPtr value)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_SlotManage(slotId, mode, value);

            return (CKR)rv;
        }

        public CKR C_EX_WrapKey(uint session,
            ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, uint keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            uint baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref uint wrappedKeyLen, ref uint key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_WrapKey(session,
                ref generationMechanism,
                keyTemplate, keyAttributeCount,
                ref derivationMechanism,
                baseKey,
                ref wrappingMechanism,
                wrappedKey, ref wrappedKeyLen, ref key);

            return (CKR)rv;
        }

        public CKR C_EX_UnwrapKey(uint session,
            ref CK_MECHANISM derivationMechanism,
            uint baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, uint wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, uint keyAttributeCount,
            ref uint key)
        {
            if (_disposed)
                throw new ObjectDisposedException(GetType().FullName);

            uint rv = _rutokenDelegates.C_EX_UnwrapKey(session,
                ref derivationMechanism,
                baseKey, ref unwrappingMechanism,
                wrappedKey, wrappedKeyLen,
                keyTemplate, keyAttributeCount,
                ref key);

            return (CKR)rv;
        }

    }
}
