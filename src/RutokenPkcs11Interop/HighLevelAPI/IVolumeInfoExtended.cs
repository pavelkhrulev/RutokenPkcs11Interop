using System;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI
{
    public interface IVolumeInfoExtended
    {
        ulong VolumeSize { get; }

        FlashAccessMode AccessMode { get; }

        CKU VolumeOwner { get; }

        ulong Flags { get; }

        ulong VolumeId { get; }
    }
}
