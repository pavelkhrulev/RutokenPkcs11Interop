using System;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI.Factories;
using Net.RutokenPkcs11Interop.Common;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.HighLevelAPI80.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public class VolumeInfoExtendedFactory : IVolumeInfoExtendedFactory
    {
        public IVolumeInfoExtended Create(ulong volumeId, ulong VolumeSize, FlashAccessMode AccessMode, CKU VolumeOwner, ulong Flags)
        {
            return new VolumeInfoExtended(volumeId, VolumeSize, AccessMode, VolumeOwner, Flags);
        }
    }
}
