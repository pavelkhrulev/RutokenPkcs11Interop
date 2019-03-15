using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI80
{
    public abstract class VolumeInfo
    {
        public ulong VolumeSize { set; get; }

        public FlashAccessMode AccessMode { set; get; }

        public CKU VolumeOwner { set; get; }

        public ulong Flags { set; get; }
    }
}
