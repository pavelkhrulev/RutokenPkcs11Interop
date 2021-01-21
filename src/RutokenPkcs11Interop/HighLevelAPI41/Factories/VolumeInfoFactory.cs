using System;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI.Factories;
using Net.RutokenPkcs11Interop.Common;

// Note: Code in this file is maintained manually

namespace Net.RutokenPkcs11Interop.HighLevelAPI41.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public class VolumeInfoFactory : IVolumeInfoFactory
    {
        public IVolumeInfo Create(ulong VolumeSize, FlashAccessMode AccessMode, CKU VolumeOwner, ulong Flags)
        {
            return new VolumeInfo(VolumeSize, AccessMode, VolumeOwner, Flags);
        }
    }
}
