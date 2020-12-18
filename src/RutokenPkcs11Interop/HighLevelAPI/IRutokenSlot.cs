using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.HighLevelAPI
{
    public interface IRutokenSlot: ISlot
    {
        ITokenInfoExtended GetTokenInfoExtended();

        void InitTokenExtended(string pin, IRutokenInitParam initParam);

        byte[] GetJournal();

        void SetLocalPIN(string userPin, string localPin, ulong localPinId);

        void SetPIN2(ulong pinId);

        ulong GetDriveSize();

        void FormatDrive(CKU userType, string pin, IEnumerable<IVolumeFormatInfoExtended> initParams);

        ICollection<IVolumeInfoExtended> GetVolumesInfo();

        void ChangeVolumeAttributes(CKU userType, string pin,
            ulong volumeId, FlashAccessMode newAccessMode, bool permanent);

        void SetActivationPassword(byte[] password);

        void SlotManage(ulong mode, byte[] value);
    }
}
