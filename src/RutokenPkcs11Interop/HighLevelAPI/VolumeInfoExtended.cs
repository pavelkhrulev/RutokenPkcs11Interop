using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class VolumeInfoExtended
    {
        private readonly HighLevelAPI41.VolumeInfoExtended _volumeInfoExtended41 = null;

        private readonly HighLevelAPI81.VolumeInfoExtended _volumeInfoExtended81 = null;

        public ulong VolumeSize
        {
            get
            {
                if (Platform.UnmanagedLongSize == 4)
                {
                    if (Platform.StructPackingSize == 0)
                    {
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                    else
                    {
                        return _volumeInfoExtended81.VolumeId;
                    }
                }
            }
        }

        internal VolumeInfoExtended(HighLevelAPI41.VolumeInfoExtended volumeInfoExtended)
        {
            if (volumeInfoExtended == null)
                throw new ArgumentNullException(nameof(volumeInfoExtended));

            _volumeInfoExtended41 = volumeInfoExtended;
        }

        internal VolumeInfoExtended(HighLevelAPI81.VolumeInfoExtended volumeInfoExtended)
        {
            if (volumeInfoExtended == null)
                throw new ArgumentNullException(nameof(volumeInfoExtended));

            _volumeInfoExtended81 = volumeInfoExtended;
        }
    }
}
