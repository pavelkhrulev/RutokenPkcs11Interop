using System.Collections.Generic;

using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;

// Note: Code in this file is maintained manually.

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{
    /// <summary>
    /// Developer rarely uses this factory to create correct IObjectHandle instances.
    /// </summary>
    public class RutokenInitParamFactory : IRutokenInitParamFactory
    {
        /// <summary>
        /// Platform specific factory for creation of IObjectHandle instances
        /// </summary>
        private IRutokenInitParamFactory _factory = null;

        /// <summary>
        /// Initializes a new instance of the ObjectHandleFactory class
        /// </summary>
        public RutokenInitParamFactory()
        {
            if (Platform.NativeULongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI40.Factories.RutokenInitParamFactory();
                else
                    _factory = new HighLevelAPI41.Factories.RutokenInitParamFactory();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _factory = new HighLevelAPI80.Factories.RutokenInitParamFactory();
                else
                    _factory = new HighLevelAPI81.Factories.RutokenInitParamFactory();
            }
        }

        public IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode)
        {
            return _factory.Create(newAdminPin, newUserPin, tokenLabel, changeUserPINPolicy, minAdminPinLen, minUserPinLen,
                maxAdminRetryCount, maxUserRetryCount, smMode);
        }

        public IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode, bool useRepairMode)
        {
            return _factory.Create(newAdminPin, newUserPin, tokenLabel, changeUserPINPolicy, minAdminPinLen, minUserPinLen,
                maxAdminRetryCount, maxUserRetryCount, smMode, useRepairMode);
        }
    }
}
