using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.LowLevelAPI81
{
    public static class Pkcs11Extensions
    {
        public static CKR C_EX_GetTokenInfoExtended(this Pkcs11 pkcs11, ulong slotId, ref CK_TOKEN_INFO_EXTENDED info)
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

            ulong rv = cGetTokenInfoExtended(slotId, ref info);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_InitToken(this Pkcs11 pkcs11, ulong slotId, byte[] pin, ref CK_RUTOKEN_INIT_PARAM initInfo)
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

            ulong pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            ulong rv = cInitToken(slotId, pin, pinLength, ref initInfo);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_UnblockUserPIN(this Pkcs11 pkcs11, ulong session)
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

            ulong rv = cUnblockUserPIN(session);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_SetTokenName(this Pkcs11 pkcs11, ulong session, byte[] label)
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

            ulong labelLength = 0;
            if (label != null)
                labelLength = Convert.ToUInt32(label.Length);

            ulong rv = cSetTokenName(session, label, labelLength);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_GetTokenName(this Pkcs11 pkcs11, ulong session, byte[] label, ref ulong labelLen)
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

            ulong rv = cGetTokenName(session, label, ref labelLen);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_GetJournal(this Pkcs11 pkcs11, ulong slotId, byte[] journal, ref ulong journalLen)
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

            ulong rv = cGetJournal(slotId, journal, ref journalLen);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_SignInvisibleInit(this Pkcs11 pkcs11, ulong session, ref CK_MECHANISM mechanism, ulong key)
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

            ulong rv = cSignInvisibleInit(session, ref mechanism, key);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_SignInvisible(this Pkcs11 pkcs11,
            ulong session, byte[] data, ulong dataLen, byte[] signature, ref ulong signatureLen)
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

            ulong rv = cSignInvisible(
                session, data, dataLen, signature, ref signatureLen);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_SetLocalPIN(this Pkcs11 pkcs11, ulong slotId, byte[] userPin,
            byte[] newLocalPin, ulong localPinId)
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

            ulong userPinLength = 0;
            if (userPin != null)
                userPinLength = Convert.ToUInt32(userPin.Length);

            ulong newLocalPinLength = 0;
            if (newLocalPin != null)
                newLocalPinLength = Convert.ToUInt32(newLocalPin.Length);

            ulong rv = cSetLocalPin(slotId, userPin, userPinLength,
                newLocalPin, newLocalPinLength, localPinId);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_GetDriveSize(this Pkcs11 pkcs11, ulong slotId, ref ulong driveSize)
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

            ulong rv = cGetDriveSize(slotId, ref driveSize);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_FormatDrive(this Pkcs11 pkcs11, ulong slotId, ulong userType,
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

            ulong pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            ulong initParamsLength = 0;
            if (initParams != null)
                initParamsLength = Convert.ToUInt32(initParams.Length);

            ulong rv = cFormatDrive(slotId, userType, pin, pinLength,
                initParams, initParamsLength);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_GetVolumesInfo(this Pkcs11 pkcs11, ulong slotId,
            CK_VOLUME_INFO_EXTENDED[] volumesInfo, ref ulong volumesInfoCount)
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

            ulong rv = cGetVolumesInfo(slotId, volumesInfo, ref volumesInfoCount);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_ChangeVolumeAttributes(this Pkcs11 pkcs11, ulong slotId, ulong userType,
            byte[] pin, ulong volumeId, FlashAccessMode newAccessMode, bool permanent)
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

            ulong pinLength = 0;
            if (pin != null)
                pinLength = Convert.ToUInt32(pin.Length);

            ulong rv = cChangeVolumeAttributes(slotId, userType,
                pin, pinLength,
                volumeId, (ulong)newAccessMode, permanent);
            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_SetLicense(this Pkcs11 pkcs11, ulong session,
            ulong licenseNum, byte[] license)
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

            ulong licenseLength = 0;
            if (license != null)
                licenseLength = Convert.ToUInt32(license.Length);

            ulong rv = cSetLicense(session, licenseNum, license, licenseLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_GetLicense(this Pkcs11 pkcs11, ulong session,
            ulong licenseNum, byte[] license, ref ulong licenseLen)
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

            ulong rv = cGetLicense(session, licenseNum, license, ref licenseLen);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_GenerateActivationPassword(this Pkcs11 pkcs11, ulong session, ulong passwordNumber,
            byte[] password, ref ulong passwordSize, ulong passwordCharacterSet)
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

            ulong rv = cGenerateActivationPassword(
                session, passwordNumber, password, ref passwordSize, passwordCharacterSet);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_LoadActivationKey(this Pkcs11 pkcs11, ulong session, byte[] key)
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

            ulong keyLength = 0;
            if (key != null)
                keyLength = Convert.ToUInt32(key.Length);

            ulong rv = cLoadActivationKey(session, key, keyLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_SetActivationPassword(this Pkcs11 pkcs11, ulong slotId, byte[] password)
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

            ulong rv = cSetActivationPassword(slotId, password);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_CreateCSR(this Pkcs11 pkcs11, ulong session,
                ulong publicKey,
                IntPtr[] dn, ulong dnLength,
                out IntPtr csr, out ulong csrLength,
                ulong privateKey,
                IntPtr[] attributes, ulong attributesLength,
                IntPtr[] extensions, ulong extensionsLength)
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

            ulong rv = cCreateCSR(session, publicKey, dn, dnLength, out csr, out csrLength, privateKey, attributes,
                attributesLength, extensions, extensionsLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_GetCertificateInfoText(this Pkcs11 pkcs11, ulong session,
                ulong cert, out IntPtr info, out ulong infoLen)
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

            ulong rv = cGetCertificateInfoText(session, cert, out info, out infoLen);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_PKCS7Sign(this Pkcs11 pkcs11, ulong session,
            byte[] data, ulong cert,
            out IntPtr envelope, out ulong encelopeLen,
            ulong privateKey,
            ulong[] certificates,
            ulong flags)
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

            ulong dataLength = 0;
            if (data != null)
                dataLength = Convert.ToUInt32(data.Length);

            ulong certificatesLength = 0;
            if (certificates != null)
                certificatesLength = Convert.ToUInt32(certificates.Length);

            ulong rv = cPkcs7Sign(session, data, dataLength,
                cert, out envelope, out encelopeLen,
                privateKey,
                certificates, certificatesLength,
                flags);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_PKCS7VerifyInit(this Pkcs11 pkcs11, ulong session,
            byte[] cms,
            ref CK_VENDOR_X509_STORE store, uint mode,
            ulong flags)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_PKCS7VerifyInit cPkcs7VerifyInit = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cPkcs7VerifyInitPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_PKCS7VerifyInit");
                cPkcs7VerifyInit = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_PKCS7VerifyInit>(cPkcs7VerifyInitPtr);
            }
            else
            {
                cPkcs7VerifyInit = RutokenNativeMethods.C_EX_PKCS7VerifyInit;
            }

            ulong cmsLength = 0;
            if (cms != null)
                cmsLength = Convert.ToUInt64(cms.Length);

            ulong rv = cPkcs7VerifyInit(session, cms, cmsLength, ref store, mode, flags);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_PKCS7Verify(this Pkcs11 pkcs11, ulong session,
            out IntPtr data, out ulong dataSize,
            out IntPtr signerCertificates, out ulong signerCertificatesCount)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_PKCS7Verify cPkcs7Verify = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cPkcs7VerifyPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_PKCS7Verify");
                cPkcs7Verify = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_PKCS7Verify>(cPkcs7VerifyPtr);
            }
            else
            {
                cPkcs7Verify = RutokenNativeMethods.C_EX_PKCS7Verify;
            }

            var rv = cPkcs7Verify(session, out data, out dataSize, out signerCertificates, out signerCertificatesCount);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_PKCS7VerifyUpdate(this Pkcs11 pkcs11, ulong session, byte[] data)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_PKCS7VerifyUpdate cPkcs7VerifyUpdate = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cPkcs7VerifyUpdatePtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_PKCS7VerifyUpdate");
                cPkcs7VerifyUpdate = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_PKCS7VerifyUpdate>(cPkcs7VerifyUpdatePtr);
            }
            else
            {
                cPkcs7VerifyUpdate = RutokenNativeMethods.C_EX_PKCS7VerifyUpdate;
            }

            ulong dataLength = 0;
            if (data != null)
                dataLength = Convert.ToUInt64(data.Length);

            var rv = cPkcs7VerifyUpdate(session, data, dataLength);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_PKCS7VerifyFinal(this Pkcs11 pkcs11, ulong session,
            out IntPtr signerCertificates, out ulong signerCertificatesCount)
        {
            if (pkcs11.Disposed)
                throw new ObjectDisposedException(pkcs11.GetType().FullName);

            RutokenDelegates.C_EX_PKCS7VerifyFinal cPkcs7VerifyFinal = null;

            if (pkcs11.LibraryHandle != IntPtr.Zero)
            {
                IntPtr cPkcs7VerifyFinalPtr = UnmanagedLibrary.GetFunctionPointer(pkcs11.LibraryHandle, "C_EX_PKCS7VerifyFinal");
                cPkcs7VerifyFinal = UnmanagedLibrary.GetDelegateForFunctionPointer<RutokenDelegates.C_EX_PKCS7VerifyFinal>(cPkcs7VerifyFinalPtr);
            }
            else
            {
                cPkcs7VerifyFinal = RutokenNativeMethods.C_EX_PKCS7VerifyFinal;
            }

            var rv = cPkcs7VerifyFinal(session, out signerCertificates, out signerCertificatesCount);

            return (CKR)Convert.ToUInt32(rv);
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

            ulong rv = cFreeBuffer(buffer);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_TokenManage(this Pkcs11 pkcs11, ulong session, ulong mode, IntPtr value)
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

            ulong rv = cTokenManage(session, mode, value);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_SlotManage(this Pkcs11 pkcs11, ulong slotId, ulong mode, IntPtr value)
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

            ulong rv = cSlotManage(slotId, mode, value);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_WrapKey(this Pkcs11 pkcs11, ulong session,
            ref CK_MECHANISM generationMechanism,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref CK_MECHANISM derivationMechanism,
            ulong baseKey,
            ref CK_MECHANISM wrappingMechanism,
            byte[] wrappedKey, ref ulong wrappedKeyLen, ref ulong key)
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

            ulong rv = cWrapKey(session,
                ref generationMechanism,
                keyTemplate, keyAttributeCount,
                ref derivationMechanism,
                baseKey,
                ref wrappingMechanism,
                wrappedKey, ref wrappedKeyLen, ref key);

            return (CKR)Convert.ToUInt32(rv);
        }

        public static CKR C_EX_UnwrapKey(this Pkcs11 pkcs11,
            ulong session,
            ref CK_MECHANISM derivationMechanism,
            ulong baseKey, ref CK_MECHANISM unwrappingMechanism,
            byte[] wrappedKey, ulong wrappedKeyLen,
            CK_ATTRIBUTE[] keyTemplate, ulong keyAttributeCount,
            ref ulong key)
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

            ulong rv = cUnwrapKey(session,
                ref derivationMechanism,
                baseKey, ref unwrappingMechanism,
                wrappedKey, wrappedKeyLen,
                keyTemplate, keyAttributeCount,
                ref key);

            return (CKR)Convert.ToUInt32(rv);
        }

    }
}
