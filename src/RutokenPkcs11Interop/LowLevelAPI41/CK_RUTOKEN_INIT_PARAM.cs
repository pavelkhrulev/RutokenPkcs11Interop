using System;
using System.Runtime.InteropServices;

using NativeULong = System.UInt32;

// Note: Code in this file is maintained manually

namespace Net.RutokenPkcs11Interop.LowLevelAPI41
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_RUTOKEN_INIT_PARAM
    {
        public NativeULong SizeofThisStructure;

        public NativeULong UseRepairMode;

        public IntPtr NewAdminPin;

        public NativeULong NewAdminPinLen;

        public IntPtr NewUserPin;

        public NativeULong NewUserPinLen;

        public NativeULong ChangeUserPINPolicy;

        public NativeULong MinAdminPinLen;

        public NativeULong MinUserPinLen;

        public NativeULong MaxAdminRetryCount;

        public NativeULong MaxUserRetryCount;

        public IntPtr TokenLabel;

        public NativeULong LabelLen;

        public NativeULong SmMode;

    }
}
