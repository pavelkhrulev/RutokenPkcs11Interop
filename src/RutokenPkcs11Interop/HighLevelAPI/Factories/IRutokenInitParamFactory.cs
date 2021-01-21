using System.Collections.Generic;

using Net.RutokenPkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI.Factories
{

    public interface IRutokenInitParamFactory
    {
        IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, ulong minAdminPinLen, ulong minUserPinLen,
            ulong maxAdminRetryCount, ulong maxUserRetryCount, ulong smMode);

        IRutokenInitParam Create(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, ulong minAdminPinLen, ulong minUserPinLen,
            ulong maxAdminRetryCount, ulong maxUserRetryCount, ulong smMode, bool useRepairMode);
    }
}
