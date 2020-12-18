using System.Collections.Generic;

using Net.RutokenPkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IRutokenInitParamFactory
    {
        IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode);

        IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode, bool useRepairMode);
    }
}
