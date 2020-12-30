using System;
using System.Collections.Generic;

using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI
{
    public interface IRutokenPkcs11Library: IPkcs11Library
    {
        List<IRutokenSlot> GetRutokenSlotList(SlotsType slotsType);
        void FreeBuffer(IntPtr buffer);
    }
}
