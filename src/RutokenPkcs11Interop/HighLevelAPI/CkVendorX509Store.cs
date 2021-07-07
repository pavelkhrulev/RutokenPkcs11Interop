using System.Collections.Generic;
using System.Linq;

namespace Net.RutokenPkcs11Interop.HighLevelAPI
{
    public class CkVendorX509Store
    {
        public IList<byte[]> TrustedCertificates { get; }
        public IList<byte[]> Certificates { get; }
        public IList<byte[]> Crls { get; }

        /// <summary>
        /// Initializes a new instance of the CkVendorX509Store class.
        /// </summary>
        /// <param name="trustedCertificates"></param>
        /// <param name="certificates"></param>
        /// <param name="crls"></param>
        public CkVendorX509Store(IList<byte[]> trustedCertificates = null, IList<byte[]> certificates = null, IList<byte[]> crls = null)
        {
            if (trustedCertificates != null && trustedCertificates.Any())
            {
                TrustedCertificates = trustedCertificates;
            }

            if (certificates != null)
            {
                Certificates = certificates;
            }

            if (crls != null)
            {
                Crls = crls;
            }
        }
    }
}
