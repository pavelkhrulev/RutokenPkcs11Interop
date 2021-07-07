namespace Net.RutokenPkcs11Interop.Common
{
    public enum VendorCrlMode
    {
        //If we have no suitable CRL - it won't be an error
        OptionalClrCheck = 0,
        // Signer's CA CRL should be passed
        LeafClrCheck = 1,
        // CRLs of all CA from the chain should be passed
        AllClrCheck = 2
    }
}
