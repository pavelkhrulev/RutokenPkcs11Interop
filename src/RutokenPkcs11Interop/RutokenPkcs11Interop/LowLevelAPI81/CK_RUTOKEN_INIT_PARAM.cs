using System;
using System.Runtime.InteropServices;

namespace RutokenPkcs11Interop.LowLevelAPI81
{
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_RUTOKEN_INIT_PARAM
    {
        public ulong SizeofThisStructure;

        public ulong UseRepairMode;

        public IntPtr NewAdminPin;

        public ulong NewAdminPinLen;

        public IntPtr NewUserPin;

        public ulong NewUserPinLen;

        public ulong ChangeUserPINPolicy;

        public ulong MinAdminPinLen;

        public ulong MinUserPinLen;

        public ulong MaxAdminRetryCount;

        public ulong MaxUserRetryCount;

        public IntPtr TokenLabel;

        public ulong LabelLen;

        public ulong SmMode;

    }
}
