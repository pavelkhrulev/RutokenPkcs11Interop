using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public interface IRutokenSlot: ISlot
    {
        ITokenInfoExtended GetTokenInfoExtended();

        void InitTokenExtended(string pin, IRutokenInitParam initParam);

        byte[] GetJournal();

        void SetLocalPIN(string userPin, string localPin, uint localPinId);

        void SetPIN2(uint pinId);

        ulong GetDriveSize();

        void FormatDrive(CKU userType, string pin, IEnumerable<IVolumeFormatInfoExtended> initParams);

        ICollection<IVolumeInfoExtended> GetVolumesInfo();

        void ChangeVolumeAttributes(CKU userType, string pin,
            uint volumeId, FlashAccessMode newAccessMode, bool permanent);

        void SetActivationPassword(byte[] password);

        void SlotManage(uint mode, byte[] value);
    }
}
