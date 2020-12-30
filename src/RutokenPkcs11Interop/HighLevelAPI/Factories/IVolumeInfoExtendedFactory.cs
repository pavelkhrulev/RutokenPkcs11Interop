using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;

// Note: Code in this file is maintained manually.

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Factory for creation of ISession instances
    /// </summary>
    public interface IVolumeInfoExtendedFactory
    {
        IVolumeInfoExtended Create(ulong volumeId, ulong VolumeSize, FlashAccessMode AccessMode, CKU VolumeOwner,ulong Flags);
    }
}
