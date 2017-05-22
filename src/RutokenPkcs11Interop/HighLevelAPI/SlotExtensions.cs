using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public static class SlotExtensions
    {
        public static TokenInfoExtended GetTokenInfoExtended(this Slot slot)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    HighLevelAPI41.TokenInfoExtended tokenInfoExtended = slot.HLA41Slot.GetTokenInfoExtended();
                    return new HighLevelAPI.TokenInfoExtended(tokenInfoExtended);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static void InitTokenExtended(this Slot slot, string pin, RutokenInitParam initParam)
        {
            if (pin == null)
                throw new ArgumentNullException(nameof(pin));

            if (initParam == null)
                throw new ArgumentNullException(nameof(initParam));

            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    slot.HLA41Slot.InitTokenExtended(pin, initParam.RutokenInitParam41);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static byte[] GetJournal(this Slot slot)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    return slot.HLA41Slot.GetJournal();
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static void SetLocalPIN(this Slot slot, string userPin, string localPin, uint localPinId)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    slot.HLA41Slot.SetLocalPIN(userPin, localPin, localPinId);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static uint GetDriveSize(this Slot slot)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    return slot.HLA41Slot.GetDriveSize();
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static void FormatDrive(this Slot slot, CKU userType,
            string pin, IEnumerable<VolumeFormatInfoExtended> initParams)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var formatParams = initParams.Select(initParam => initParam.VolumeFormatInfoExtended41)
                                                  .ToList();
                    slot.HLA41Slot.FormatDrive(userType, pin, formatParams);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static ICollection<VolumeInfoExtended> GetVolumesInfo(this Slot slot)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var volumesInfo = slot.HLA41Slot.GetVolumesInfo();
                    return volumesInfo.Select(volumeInfo => new VolumeInfoExtended(volumeInfo))
                                      .ToList();
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static void ChangeVolumeAttributes(this Slot slot, CKU userType, string pin,
            uint volumeId, FlashAccessMode newAccessMode, bool permanent)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    slot.HLA41Slot.ChangeVolumeAttributes(userType, pin, volumeId, newAccessMode, permanent);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        public static void SetActivationPassword(this Slot slot, byte[] password)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    slot.HLA41Slot.SetActivationPassword(password);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }
    }
}
