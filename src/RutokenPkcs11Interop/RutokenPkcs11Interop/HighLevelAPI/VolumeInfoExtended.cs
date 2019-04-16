using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class VolumeInfoExtended
    {
        private readonly HighLevelAPI40.VolumeInfoExtended _volumeInfoExtended40 = null;

        private readonly HighLevelAPI41.VolumeInfoExtended _volumeInfoExtended41 = null;

        private readonly HighLevelAPI80.VolumeInfoExtended _volumeInfoExtended80 = null;

        private readonly HighLevelAPI81.VolumeInfoExtended _volumeInfoExtended81 = null;

        public ulong VolumeSize
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended40.VolumeSize;
                    }
                    else
                    {
                        return _volumeInfoExtended41.VolumeSize;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended80.VolumeSize;
                    }
                    else
                    {
                        return _volumeInfoExtended81.VolumeSize;
                    }
                }
            }
        }

        public FlashAccessMode AccessMode
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended40.AccessMode;
                    }
                    else
                    {
                        return _volumeInfoExtended41.AccessMode;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended80.AccessMode;
                    }
                    else
                    {
                        return _volumeInfoExtended81.AccessMode;
                    }
                }
            }
        }

        public CKU VolumeOwner
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended40.VolumeOwner;
                    }
                    else
                    {
                        return _volumeInfoExtended41.VolumeOwner;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended80.VolumeOwner;
                    }
                    else
                    {
                        return _volumeInfoExtended81.VolumeOwner;
                    }
                }
            }
        }

        public ulong Flags
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended40.Flags;
                    }
                    else
                    {
                        return _volumeInfoExtended41.Flags;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended80.Flags;
                    }
                    else
                    {
                        return _volumeInfoExtended81.Flags;
                    }
                }
            }
        }

        public ulong VolumeId
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended40.VolumeId;
                    }
                    else
                    {
                        return _volumeInfoExtended41.VolumeId;
                    }
                }
                else
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        return _volumeInfoExtended80.VolumeId;
                    }
                    else
                    {
                        return _volumeInfoExtended81.VolumeId;
                    }
                }
            }
        }

        internal VolumeInfoExtended(HighLevelAPI40.VolumeInfoExtended volumeInfoExtended)
        {
            if (volumeInfoExtended == null)
                throw new ArgumentNullException(nameof(volumeInfoExtended));

            _volumeInfoExtended40 = volumeInfoExtended;
        }

        internal VolumeInfoExtended(HighLevelAPI41.VolumeInfoExtended volumeInfoExtended)
        {
            if (volumeInfoExtended == null)
                throw new ArgumentNullException(nameof(volumeInfoExtended));

            _volumeInfoExtended41 = volumeInfoExtended;
        }

        internal VolumeInfoExtended(HighLevelAPI80.VolumeInfoExtended volumeInfoExtended)
        {
            if (volumeInfoExtended == null)
                throw new ArgumentNullException(nameof(volumeInfoExtended));

            _volumeInfoExtended80 = volumeInfoExtended;
        }

        internal VolumeInfoExtended(HighLevelAPI81.VolumeInfoExtended volumeInfoExtended)
        {
            if (volumeInfoExtended == null)
                throw new ArgumentNullException(nameof(volumeInfoExtended));

            _volumeInfoExtended81 = volumeInfoExtended;
        }
    }
}
