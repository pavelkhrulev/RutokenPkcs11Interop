using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class VolumeFormatInfoExtended
    {
        internal HighLevelAPI40.VolumeFormatInfoExtended VolumeFormatInfoExtended40 { get; }

        internal HighLevelAPI41.VolumeFormatInfoExtended VolumeFormatInfoExtended41 { get; }

        internal HighLevelAPI80.VolumeFormatInfoExtended VolumeFormatInfoExtended80 { get; }

        internal HighLevelAPI81.VolumeFormatInfoExtended VolumeFormatInfoExtended81 { get; }

        public VolumeFormatInfoExtended(ulong volumeSize, FlashAccessMode accessMode, CKU userType, uint flags)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    VolumeFormatInfoExtended40 =
                        new HighLevelAPI40.VolumeFormatInfoExtended(
                            Convert.ToUInt32(volumeSize), accessMode, userType, flags);
                else
                    VolumeFormatInfoExtended41 =
                        new HighLevelAPI41.VolumeFormatInfoExtended(
                            Convert.ToUInt32(volumeSize), accessMode, userType, flags);
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    VolumeFormatInfoExtended80 =
                        new HighLevelAPI80.VolumeFormatInfoExtended(
                            volumeSize, accessMode, userType, flags);
                else
                    VolumeFormatInfoExtended81 =
                        new HighLevelAPI81.VolumeFormatInfoExtended(
                            volumeSize, accessMode, userType, flags);
            }
        }
    }
}
