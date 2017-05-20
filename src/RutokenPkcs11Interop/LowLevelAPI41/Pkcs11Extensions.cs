using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;

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

        public static CKR C_EX_InitToken(this Pkcs11 pkcs11, uint slotId, byte[] pin, uint pinLen, ref CK_RUTOKEN_INIT_PARAM initInfo)
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

            uint rv = cInitToken(slotId, pin, pinLen, ref initInfo);
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

        public static CKR C_EX_SetTokenName(this Pkcs11 pkcs11, uint session, byte[] label, uint labelLen)
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

            uint rv = cSetTokenName(session, label, labelLen);
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

        public static CKR C_EX_SetLocalPIN(this Pkcs11 pkcs11, uint slotId, byte[] userPin, uint userPinLen,
            byte[] newLocalPin, uint newLocalPinLen, uint localPinId)
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

            uint rv = cSetLocalPin(slotId, userPin, userPinLen, newLocalPin, newLocalPinLen, localPinId);
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
    }
}
