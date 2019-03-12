using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class VolumeFormatInfoExtended
    {
        internal HighLevelAPI41.VolumeFormatInfoExtended VolumeFormatInfoExtended41 { get; }

        internal HighLevelAPI81.VolumeFormatInfoExtended VolumeFormatInfoExtended81 { get; }

        public VolumeFormatInfoExtended(ulong volumeSize, FlashAccessMode accessMode, CKU userType, uint flags)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    throw new NotImplementedException();
                else
                    VolumeFormatInfoExtended41 =
                        new HighLevelAPI41.VolumeFormatInfoExtended(
                            Convert.ToUInt32(volumeSize), accessMode, userType, flags);
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    throw new NotImplementedException();
                else
                    VolumeFormatInfoExtended81 =
                        new HighLevelAPI81.VolumeFormatInfoExtended(
                            volumeSize, accessMode, userType, flags);
            }
        }
    }
}
