using System.Collections.Generic;

using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI.Factories;
using Net.RutokenPkcs11Interop.HighLevelAPI;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.HighLevelAPI81.Factories
{
    /// <summary>
    /// Developer rarely uses this factory to create correct IObjectHandle instances.
    /// </summary>
    public class RutokenInitParamFactory : IRutokenInitParamFactory
    {
        public IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, ulong minAdminPinLen, ulong minUserPinLen,
            ulong maxAdminRetryCount, ulong maxUserRetryCount, ulong smMode)
        {
            return new RutokenInitParam(newAdminPin, newUserPin, tokenLabel, changeUserPINPolicy, minAdminPinLen, minUserPinLen, 
                maxAdminRetryCount, maxUserRetryCount, smMode);
        }

        public IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, ulong minAdminPinLen, ulong minUserPinLen,
            ulong maxAdminRetryCount, ulong maxUserRetryCount, ulong smMode, bool useRepairMode)
        {
            return new RutokenInitParam(newAdminPin, newUserPin, tokenLabel, changeUserPINPolicy, minAdminPinLen, minUserPinLen,
            maxAdminRetryCount, maxUserRetryCount, smMode, useRepairMode);
        }
    }
}
