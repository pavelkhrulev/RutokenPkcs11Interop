using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI41
{
    public static class Pkcs11Extensions
    {
        public static CKR C_EX_GetTokenInfoExtended(this Pkcs11 pkcs11, uint slotId, ref CK_TOKEN_INFO_EXTENDED info)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_GetTokenInfoExtendedDelegate cGetTokenInfoExtended = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGetTokenInfoExtendedPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_GetTokenInfoExtended");
                cGetTokenInfoExtended = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_GetTokenInfoExtendedDelegate>(cGetTokenInfoExtendedPtr);
            }
            else
            {
                cGetTokenInfoExtended = RutokenNativeMethods.C_EX_GetTokenInfoExtended;
            }

            uint rv = cGetTokenInfoExtended(slotId, ref info);
            return (CKR)rv;
        }

        public static CKR C_EX_InitToken(this Pkcs11 pkcs11, uint slotId, byte[] pin, ref CK_RUTOKEN_INIT_PARAM initInfo)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_InitToken cInitToken = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cInitTokenPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_InitToken");
                cInitToken = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_InitToken>(cInitTokenPtr);
            }
            else
            {
                cInitToken = RutokenNativeMethods.C_EX_InitToken;
            }

            uint pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            uint rv = cInitToken(slotId, pin, pinLength, ref initInfo);
            return (CKR)rv;
        }

        public static CKR C_EX_UnblockUserPIN(this Pkcs11 pkcs11, uint session)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_UnblockUserPIN cUnblockUserPIN = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cUnblockUserPINPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_UnblockUserPIN");
                cUnblockUserPIN = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_UnblockUserPIN>(cUnblockUserPINPtr);
            }
            else
            {
                cUnblockUserPIN = RutokenNativeMethods.C_EX_UnblockUserPIN;
            }

            uint rv = cUnblockUserPIN(session);
            return (CKR)rv;
        }

        public static CKR C_EX_SetTokenName(this Pkcs11 pkcs11, uint session, byte[] label)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_SetTokenName cSetTokenName = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cSetTokenNamePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_SetTokenName");
                cSetTokenName = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_SetTokenName>(cSetTokenNamePtr);
            }
            else
            {
                cSetTokenName = RutokenNativeMethods.C_EX_SetTokenName;
            }

            uint labelLength = 0;
            if (label != null)
                labelLength = Convert.ToUInt32(label.Length);

            uint rv = cSetTokenName(session, label, labelLength);
            return (CKR)rv;
        }

        public static CKR C_EX_GetTokenName(this Pkcs11 pkcs11, uint session, byte[] label, ref uint labelLen)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_GetTokenName cGetTokenName = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGetTokenNamePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_GetTokenName");
                cGetTokenName = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_GetTokenName>(cGetTokenNamePtr);
            }
            else
            {
                cGetTokenName = RutokenNativeMethods.C_EX_GetTokenName;
            }

            uint rv = cGetTokenName(session, label, ref labelLen);
            return (CKR)rv;
        }

        public static CKR C_EX_GetJournal(this Pkcs11 pkcs11, uint slotId, byte[] journal, ref uint journalLen)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_GetJournal cGetJournal = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGetJournalPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_GetJournal");
                cGetJournal = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_GetJournal>(cGetJournalPtr);
            }
            else
            {
                cGetJournal = RutokenNativeMethods.C_EX_GetJournal;
            }

            uint rv = cGetJournal(slotId, journal, ref journalLen);
            return (CKR)rv;
        }

        public static CKR C_EX_SignInvisibleInit(this Pkcs11 pkcs11, uint session, ref CK_MECHANISM mechanism, uint key)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_SignInvisibleInit cSignInvisibleInit = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cSignInvisibleInitPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_SignInvisibleInit");
                cSignInvisibleInit = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_SignInvisibleInit>(cSignInvisibleInitPtr);
            }
            else
            {
                cSignInvisibleInit = RutokenNativeMethods.C_EX_SignInvisibleInit;
            }

            uint rv = cSignInvisibleInit(session, ref mechanism, key);
            return (CKR)rv;
        }

        public static CKR C_EX_SignInvisible(this Pkcs11 pkcs11,
            uint session, byte[] data, uint dataLen, byte[] signature, ref uint signatureLen)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_SignInvisible cSignInvisible = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cSignInvisiblePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_SignInvisible");
                cSignInvisible = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_SignInvisible>(cSignInvisiblePtr);
            }
            else
            {
                cSignInvisible = RutokenNativeMethods.C_EX_SignInvisible;
            }

            uint rv = cSignInvisible(
                session, data, dataLen, signature, ref signatureLen);
            return (CKR)rv;
        }

        public static CKR C_EX_SetLocalPIN(this Pkcs11 pkcs11, uint slotId, byte[] userPin,
            byte[] newLocalPin, uint localPinId)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_SetLocalPIN cSetLocalPin = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cSetLocalPinPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_SetLocalPIN");
                cSetLocalPin = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_SetLocalPIN>(cSetLocalPinPtr);
            }
            else
            {
                cSetLocalPin = RutokenNativeMethods.C_EX_SetLocalPIN;
            }

            uint userPinLength = 0;
            if (userPin != null)
                userPinLength = Convert.ToUInt32(userPin.Length);

            uint newLocalPinLength = 0;
            if (newLocalPin != null)
                newLocalPinLength = Convert.ToUInt32(newLocalPin.Length);

            uint rv = cSetLocalPin(slotId, userPin, userPinLength,
                newLocalPin, newLocalPinLength, localPinId);
            return (CKR)rv;
        }

        public static CKR C_EX_GetDriveSize(this Pkcs11 pkcs11, uint slotId, ref uint driveSize)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_GetDriveSize cGetDriveSize = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGetDriveSizePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_GetDriveSize");
                cGetDriveSize = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_GetDriveSize>(cGetDriveSizePtr);
            }
            else
            {
                cGetDriveSize = RutokenNativeMethods.C_EX_GetDriveSize;
            }

            uint rv = cGetDriveSize(slotId, ref driveSize);
            return (CKR)rv;
        }

        public static CKR C_EX_FormatDrive(this Pkcs11 pkcs11, uint slotId, uint userType,
            byte[] pin, CK_VOLUME_FORMAT_INFO_EXTENDED[] initParams)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_FormatDrive cFormatDrive = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cFormatDrivePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_FormatDrive");
                cFormatDrive = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_FormatDrive>(cFormatDrivePtr);
            }
            else
            {
                cFormatDrive = RutokenNativeMethods.C_EX_FormatDrive;
            }

            uint pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            uint initParamsLength = 0;
            if (initParams != null)
                initParamsLength = Convert.ToUInt32(initParams.Length);

            uint rv = cFormatDrive(slotId, userType, pin, pinLength,
                initParams, initParamsLength);
            return (CKR)rv;
        }

        public static CKR C_EX_GetVolumesInfo(this Pkcs11 pkcs11, uint slotId,
            CK_VOLUME_INFO_EXTENDED[] volumesInfo, ref uint volumesInfoCount)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_GetVolumesInfo cGetVolumesInfo = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGetVolumesInfoPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_GetVolumesInfo");
                cGetVolumesInfo = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_GetVolumesInfo>(cGetVolumesInfoPtr);
            }
            else
            {
                cGetVolumesInfo = RutokenNativeMethods.C_EX_GetVolumesInfo;
            }

            uint rv = cGetVolumesInfo(slotId, volumesInfo, ref volumesInfoCount);
            return (CKR)rv;
        }

        public static CKR C_EX_ChangeVolumeAttributes(this Pkcs11 pkcs11, uint slotId, uint userType,
            byte[] pin, uint volumeId, FlashAccessMode newAccessMode, bool permanent)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_ChangeVolumeAttributes cChangeVolumeAttributes = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cChangeVolumeAttributesPtr = UnmanagedLibrary.GetFunctionPointer(
                    pkcs11.LibraryHandle, "C_EX_ChangeVolumeAttributes");
                cChangeVolumeAttributes = UnmanagedLibrary.GetDelegateForFunctionPointer
                    <RutokenDelegates.C_EX_ChangeVolumeAttributes>(cChangeVolumeAttributesPtr);
            }
            else
            {
                cChangeVolumeAttributes = RutokenNativeMethods.C_EX_ChangeVolumeAttributes;
            }

            uint pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            uint rv = cChangeVolumeAttributes(slotId, userType,
                pin, pinLength,
                volumeId, (uint)newAccessMode, permanent);
            return (CKR)rv;
        }

        public static CKR C_EX_SetLicense(this Pkcs11 pkcs11, uint session,
            uint licenseNum, byte[] license)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_SetLicense cSetLicense = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cSetLicensePtr = UnmanagedLibrary.GetFunctionPointer(
                    pkcs11.LibraryHandle, "C_EX_SetLicense");
                cSetLicense = UnmanagedLibrary.GetDelegateForFunctionPointer
                    <RutokenDelegates.C_EX_SetLicense>(cSetLicensePtr);
            }
            else
            {
                cSetLicense = RutokenNativeMethods.C_EX_SetLicense;
            }

            uint licenseLength = 0;
            if (license != null)
                licenseLength = Convert.ToUInt32(license.Length);

            uint rv = cSetLicense(session, licenseNum, license, licenseLength);

            return (CKR)rv;
        }

        public static CKR C_EX_GetLicense(this Pkcs11 pkcs11, uint session,
            uint licenseNum, byte[] license, ref uint licenseLen)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_GetLicense cGetLicense = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGetLicensePtr = UnmanagedLibrary.GetFunctionPointer(
                    pkcs11.LibraryHandle, "C_EX_GetLicense");
                cGetLicense = UnmanagedLibrary.GetDelegateForFunctionPointer
                    <RutokenDelegates.C_EX_GetLicense>(cGetLicensePtr);
            }
            else
            {
                cGetLicense = RutokenNativeMethods.C_EX_GetLicense;
            }

            uint rv = cGetLicense(session, licenseNum, license, ref licenseLen);

            return (CKR)rv;
        }

        public static CKR C_EX_GenerateActivationPassword(this Pkcs11 pkcs11, uint session, uint passwordNumber,
            byte[] password, ref uint passwordSize, uint passwordCharacterSet)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_GenerateActivationPassword cGenerateActivationPassword = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGenerateActivationPasswordPtr = UnmanagedLibrary.GetFunctionPointer(
                    pkcs11.LibraryHandle, "C_EX_GenerateActivationPassword");
                cGenerateActivationPassword = UnmanagedLibrary.GetDelegateForFunctionPointer
                    <RutokenDelegates.C_EX_GenerateActivationPassword>(cGenerateActivationPasswordPtr);
            }
            else
            {
                cGenerateActivationPassword = RutokenNativeMethods.C_EX_GenerateActivationPassword;
            }

            uint rv = cGenerateActivationPassword(
                session, passwordNumber, password, ref passwordSize, passwordCharacterSet);

            return (CKR)rv;
        }

        public static CKR C_EX_LoadActivationKey(this Pkcs11 pkcs11, uint session, byte[] key)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_LoadActivationKey cLoadActivationKey = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cLoadActivationKeyPtr = UnmanagedLibrary.GetFunctionPointer(
                    pkcs11.LibraryHandle, "C_EX_LoadActivationKey");
                cLoadActivationKey = UnmanagedLibrary.GetDelegateForFunctionPointer
                    <RutokenDelegates.C_EX_LoadActivationKey>(cLoadActivationKeyPtr);
            }
            else
            {
                cLoadActivationKey = RutokenNativeMethods.C_EX_LoadActivationKey;
            }

            uint keyLength = 0;
            if (key != null)
                keyLength = Convert.ToUInt32(key.Length);

            uint rv = cLoadActivationKey(session, key, keyLength);

            return (CKR)rv;
        }

        public static CKR C_EX_SetActivationPassword(this Pkcs11 pkcs11, uint slotId, byte[] password)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_SetActivationPassword cSetActivationPassword = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cSetActivationPasswordPtr = UnmanagedLibrary.GetFunctionPointer(
                    pkcs11.LibraryHandle, "C_EX_SetActivationPassword");
                cSetActivationPassword = UnmanagedLibrary.GetDelegateForFunctionPointer
                    <RutokenDelegates.C_EX_SetActivationPassword>(cSetActivationPasswordPtr);
            }
            else
            {
                cSetActivationPassword = RutokenNativeMethods.C_EX_SetActivationPassword;
            }

            uint rv = cSetActivationPassword(slotId, password);

            return (CKR)rv;
        }

        public static CKR C_EX_CreateCSR(this Pkcs11 pkcs11, uint session,
                uint publicKey,
                IntPtr[] dn, uint dnLength,
                out IntPtr csr, out uint csrLength,
                uint privateKey,
                IntPtr[] attributes, uint attributesLength,
                IntPtr[] extensions, uint extensionsLength)
        {
            RutokenDelegates.C_EX_CreateCSR cCreateCSR = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cCreateCSRPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_CreateCSR");
                cCreateCSR = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_CreateCSR>(cCreateCSRPtr);
            }
            else
            {
                cCreateCSR = RutokenNativeMethods.C_EX_CreateCSR;
            }

            uint rv = cCreateCSR(session, publicKey, dn, dnLength, out csr, out csrLength, privateKey, attributes,
                attributesLength, extensions, extensionsLength);

            return (CKR)rv;
        }

        public static CKR C_EX_GetCertificateInfoText(this Pkcs11 pkcs11, uint session,
                uint cert, out IntPtr info, out uint infoLen)
        {
            RutokenDelegates.C_EX_GetCertificateInfoText cGetCertificateInfoText = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cGetCertificateInfoTextPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_GetCertificateInfoText");
                cGetCertificateInfoText = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_GetCertificateInfoText>(cGetCertificateInfoTextPtr);
            }
            else
            {
                cGetCertificateInfoText = RutokenNativeMethods.C_EX_GetCertificateInfoText;
            }

            uint rv = cGetCertificateInfoText(session, cert, out info, out infoLen);

            return (CKR)rv;
        }

        public static CKR C_EX_PKCS7Sign(this Pkcs11 pkcs11, uint session,
            byte[] data, uint cert,
            out IntPtr envelope, out uint encelopeLen,
            uint privateKey,
            uint[] certificates,
            uint flags)
        {
            RutokenDelegates.C_EX_PKCS7Sign cPkcs7Sign = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cPkcs7SignPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_PKCS7Sign");
                cPkcs7Sign = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_PKCS7Sign>(cPkcs7SignPtr);
            }
            else
            {
                cPkcs7Sign = RutokenNativeMethods.C_EX_PKCS7Sign;
            }

            uint dataLength = 0;
            if (data != null)
                dataLength = Convert.ToUInt32(data.Length);

            uint certificatesLength = 0;
            if (certificates != null)
                certificatesLength = Convert.ToUInt32(certificates.Length);

            uint rv = cPkcs7Sign(session, data, dataLength,
                cert, out envelope, out encelopeLen,
                privateKey,
                certificates, certificatesLength,
                flags);

            return (CKR)rv;
        }

        public static CKR C_EX_FreeBuffer(this Pkcs11 pkcs11, IntPtr buffer)
        {
            RutokenDelegates.C_EX_FreeBuffer cFreeBuffer = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cFreeBufferPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_FreeBuffer");
                cFreeBuffer = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_FreeBuffer>(cFreeBufferPtr);
            }
            else
            {
                cFreeBuffer = RutokenNativeMethods.C_EX_FreeBuffer;
            }

            uint rv = cFreeBuffer(buffer);

            return (CKR)rv;
        }

        public static CKR C_EX_TokenManage(this Pkcs11 pkcs11, uint session, uint mode, IntPtr value)
        {
            RutokenDelegates.C_EX_TokenManage cTokenManage = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cTokenManagePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_TokenManage");
                cTokenManage = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_TokenManage>(cTokenManagePtr);
            }
            else
            {
                cTokenManage = RutokenNativeMethods.C_EX_TokenManage;
            }

            uint rv = cTokenManage(session, mode, value);

            return (CKR)rv;
        }

        public static CKR C_EX_SlotManage(this Pkcs11 pkcs11, uint slotId, uint mode, IntPtr value)
        {
            RutokenDelegates.C_EX_SlotManage cSlotManage = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cSlotManagePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_SlotManage");
                cSlotManage = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_SlotManage>(cSlotManagePtr);
            }
            else
            {
                cSlotManage = RutokenNativeMethods.C_EX_TokenManage;
            }

            uint rv = cSlotManage(slotId, mode, value);

            return (CKR)rv;
        }

        public static CKR C_EX_WrapKey(this Pkcs11 pkcs11, uint session,
            ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, uint keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            uint baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref uint wrappedKeyLen, ref uint key)
        {
            RutokenDelegates.C_EX_WrapKey cWrapKey = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cWrapKeyPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_WrapKey");
                cWrapKey = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_WrapKey>(cWrapKeyPtr);
            }
            else
            {
                cWrapKey = RutokenNativeMethods.C_EX_WrapKey;
            }

            uint rv = cWrapKey(session,
                ref generationMechanism,
                keyTemplate, keyAttributeCount,
                ref derivationMechanism,
                baseKey,
                ref wrappingMechanism,
                wrappedKey, ref wrappedKeyLen, ref key);

            return (CKR)rv;
        }

        public static CKR C_EX_UnwrapKey(this Pkcs11 pkcs11,
            uint session,
            ref CK_MECHANISM derivationMechanism,
            uint baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, uint wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, uint keyAttributeCount,
            ref uint key)
        {
            RutokenDelegates.C_EX_UnwrapKey cUnwrapKey = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cUnwrapKeyPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_UnwrapKey");
                cUnwrapKey = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_UnwrapKey>(cUnwrapKeyPtr);
            }
            else
            {
                cUnwrapKey = RutokenNativeMethods.C_EX_UnwrapKey;
            }

            uint rv = cUnwrapKey(session,
                ref derivationMechanism,
                baseKey, ref unwrappingMechanism,
                wrappedKey, wrappedKeyLen,
                keyTemplate, keyAttributeCount,
                ref key);

            return (CKR)rv;
        }

    }
}
