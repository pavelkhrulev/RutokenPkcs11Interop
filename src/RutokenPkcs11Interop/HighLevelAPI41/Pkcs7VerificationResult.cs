using System.Collections.Generic;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public class Pkcs7VerificationResult
    {
        public ICollection<byte[]> Certificates { get; set; }

        public byte[] Data { get; set; }

        public bool IsValid { get; set; }
    }
}
