using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class VolumeInfoExtended
    {
        private readonly HighLevelAPI41.VolumeInfoExtended _volumeInfoExtended41 = null;

        public uint VolumeSize
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
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
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint Flags
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
                        throw new NotImplementedException();
                    }
                }
            }
        }

        public uint VolumeId
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
                        throw new NotImplementedException();
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
    }
}
