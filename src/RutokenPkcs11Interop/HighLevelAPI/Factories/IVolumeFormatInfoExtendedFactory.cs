﻿using Net.RutokenPkcs11Interop.Common;
using Net.Pkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IVolumeFormatInfoExtendedFactory
    {
        IVolumeFormatInfoExtended Create(ulong volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, ulong flags);
    }
}
