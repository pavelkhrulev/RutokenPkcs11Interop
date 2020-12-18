using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.Factories;

// Note: Code in this file is generated automatically.

namespace Net.RutokenPkcs11Interop.HighLevelAPI81.Factories
{
    /// <summary>
    /// Factory for creation of ISlot instances
    /// </summary>
    public class RutokenSlotFactory : ISlotFactory
    {
        /// <summary>
        /// Creates slot with specified handle
        /// </summary>
        /// <param name="factories">Factories to be used by Developer and Pkcs11Interop library</param>
        /// <param name="pkcs11Library">Low level PKCS#11 wrapper</param>
        /// <param name="slotId">PKCS#11 handle of slot</param>
        public ISlot Create(Pkcs11InteropFactories factories, LowLevelPkcs11Library pkcs11Library, ulong slotId)
        {
            LowLevelAPI81.RutokenPkcs11Library p11 = pkcs11Library as LowLevelAPI81.RutokenPkcs11Library;
            if (p11 == null)
                throw new ArgumentException("Incorrect type of low level PKCS#11 wrapper");

            return new RutokenSlot(factories, p11, slotId);
        }
    }
}
