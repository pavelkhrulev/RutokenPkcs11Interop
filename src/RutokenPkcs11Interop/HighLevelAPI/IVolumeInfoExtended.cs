using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
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
