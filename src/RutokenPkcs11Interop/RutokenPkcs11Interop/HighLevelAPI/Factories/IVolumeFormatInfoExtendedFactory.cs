using RutokenPkcs11Interop.Common;
using Net.Pkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IVolumeFormatInfoExtendedFactory
    {
        IVolumeFormatInfoExtended Create(uint volumeSize, FlashAccessMode accessMode,
            CKU volumeOwner, uint flags);
    }
}
