using System;
using System.Runtime.InteropServices;
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

            uint rv = cInitToken(slotId, pin, Convert.ToUInt32(pin.Length), ref initInfo);
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

            uint rv = cSetTokenName(session, label, Convert.ToUInt32(label.Length));
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

            uint rv = cSetLocalPin(slotId, userPin, Convert.ToUInt32(userPin.Length),
                newLocalPin, Convert.ToUInt32(newLocalPin.Length), localPinId);
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

            uint rv = cFormatDrive(slotId, userType, pin, Convert.ToUInt32(pin.Length),
                initParams, Convert.ToUInt32(initParams.Length));
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

            uint rv = cChangeVolumeAttributes(slotId, userType,
                pin, Convert.ToUInt32(pin.Length),
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

            uint rv = cSetLicense(session, licenseNum, license, Convert.ToUInt32(license.Length));

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

            uint rv = cLoadActivationKey(session, key, Convert.ToUInt32(key.Length));

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
    }
}
