using System.Collections.Generic;

using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI.Factories;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11Interop.HighLevelAPI80.Factories
{
    /// <summary>
    /// Developer rarely uses this factory to create correct IObjectHandle instances.
    /// </summary>
    public class RutokenInitParamFactory : IRutokenInitParamFactory
    {
        public IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode)
        {
            return new RutokenInitParam(newAdminPin, newUserPin, tokenLabel, changeUserPINPolicy, minAdminPinLen, minUserPinLen, 
                maxAdminRetryCount, maxUserRetryCount, smMode);
        }

        public IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode, bool useRepairMode)
        {
            return new RutokenInitParam(newAdminPin, newUserPin, tokenLabel, changeUserPINPolicy, minAdminPinLen, minUserPinLen,
            maxAdminRetryCount, maxUserRetryCount, smMode, useRepairMode);
        }
    }
}
