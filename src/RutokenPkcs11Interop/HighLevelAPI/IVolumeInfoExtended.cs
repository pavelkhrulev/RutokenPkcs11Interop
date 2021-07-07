using System;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI
{
    public interface IVolumeInfoExtended : IVolumeInfo
    {
        ulong VolumeId { get; }
    }
}
