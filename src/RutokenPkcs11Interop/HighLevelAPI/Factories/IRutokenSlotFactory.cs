using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IRutokenSlotFactory: ISlotFactory
    {
        IRutokenSlot CreateRutoken(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong slotId);
    }
}
