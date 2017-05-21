using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public abstract class VolumeInfo
    {
        public uint VolumeSize { set; get; }

        public FlashAccessMode AccessMode { set; get; }

        public CKU VolumeOwner { set; get; }

        public uint Flags { set; get; }
    }
}
