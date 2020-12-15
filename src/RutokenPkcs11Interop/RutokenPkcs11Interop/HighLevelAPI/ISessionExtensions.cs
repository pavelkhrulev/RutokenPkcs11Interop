using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Helpers;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public interface ISessionExtensions: ISession
    {
        void UnblockUserPIN();

        void SetTokenName(string label);

        string GetTokenLabel();

        void SetLicense(uint licenseNum, byte[] license);

        byte[] GetLicense(uint licenseNum);

        void LoadActivationKey(byte[] key);

        byte[] GenerateActivationPassword(ActivationPasswordNumber passwordNumber, ActivationPasswordCharacterSet characterSet);

        byte[] SignInvisible(IMechanism mechanism, IObjectHandle keyHandle, byte[] data);

        string CreateCSR(IObjectHandle publicKey,
            string[] dn, IObjectHandle privateKey,
            string[] attributes, string[] extensions);

        string GetCertificateInfoText(IObjectHandle certificate);

        byte[] PKCS7Sign(byte[] data, IObjectHandle certificate,
            IObjectHandle privateKey, uint[] certificates, uint flags);

        Pkcs7VerificationResult PKCS7Verify(byte[] cms,
            CkVendorX509Store vendorX509Store,
            VendorCrlMode mode, uint flags);

        Pkcs7VerificationResult PKCS7Verify(byte[] cms,
            Stream inputStream,
            CkVendorX509Store vendorX509Store,
            VendorCrlMode mode, uint flags);

        void TokenManage(TokenManageMode mode, byte[] value);

        byte[] ExtendedWrapKey(
            IMechanism generationMechanism, List<IObjectAttribute> keyAttributes,
            IMechanism derivationMechanism, IObjectHandle baseKey,
            IMechanism wrappingMechanism, ref IObjectHandle key);

        IObjectHandle ExtendedUnwrapKey(
            IMechanism derivationMechanism, IObjectHandle baseKey,
            IMechanism unwrappingMechanism,
            byte[] wrappedKey, List<IObjectAttribute> keyAttributes);

        PinPolicy GetPinPolicy(CKU userType);

        void SetPinPolicy(PinPolicy pinPolicy, CKU userType);

        bool PinPolicySupports(CKU userType);
    }
}
