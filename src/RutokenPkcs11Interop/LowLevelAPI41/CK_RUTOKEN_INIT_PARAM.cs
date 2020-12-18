using System;
using System.Runtime.InteropServices;

namespace Net.RutokenPkcs11Interop.LowLevelAPI41
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_RUTOKEN_INIT_PARAM
    {
        public uint SizeofThisStructure;

        public uint UseRepairMode;

        public IntPtr NewAdminPin;

        public uint NewAdminPinLen;

        public IntPtr NewUserPin;

        public uint NewUserPinLen;

        public uint ChangeUserPINPolicy;

        public uint MinAdminPinLen;

        public uint MinUserPinLen;

        public uint MaxAdminRetryCount;

        public uint MaxUserRetryCount;

        public IntPtr TokenLabel;

        public uint LabelLen;

        public uint SmMode;

    }
}
