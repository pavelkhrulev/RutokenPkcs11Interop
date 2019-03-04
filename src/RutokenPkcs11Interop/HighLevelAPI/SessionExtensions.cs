using System;
using System.Collections.Generic;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.HighLevelAPI41;
using RutokenPkcs11Interop.HighLevelAPI81;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public static class SessionExtensions
    {
        public static void UnblockUserPIN(this Session session)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    session.HLA41Session.UnblockUserPIN();
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
                    session.HLA81Session.UnblockUserPIN();
                }
            }
        }

        public static void SetTokenName(this Session session, string label)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    session.HLA41Session.SetTokenName(label);
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
                    session.HLA81Session.SetTokenName(label);
                }
            }
        }

        public static string GetTokenLabel(this Session session)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    return session.HLA41Session.GetTokenLabel();
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
                    return session.HLA81Session.GetTokenLabel();
                }
            }
        }

        public static void SetLicense(this Session session, uint licenseNum, byte[] license)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    session.HLA41Session.SetLicense(licenseNum, license);
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
                    session.HLA81Session.SetLicense(licenseNum, license);
                }
            }
        }

        public static byte[] GetLicense(this Session session, uint licenseNum)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    return session.HLA41Session.GetLicense(licenseNum);
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
                    return session.HLA81Session.GetLicense(licenseNum);
                }
            }
        }

        public static void LoadActivationKey(this Session session, byte[] key)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    session.HLA41Session.LoadActivationKey(key);
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
                    session.HLA81Session.LoadActivationKey(key);
                }
            }
        }

        public static byte[] GenerateActivationPassword(this Session session,
            ActivationPasswordNumber passwordNumber, ActivationPasswordCharacterSet characterSet)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    return session.HLA41Session.GenerateActivationPassword(passwordNumber, characterSet);
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
                    return session.HLA81Session.GenerateActivationPassword(passwordNumber, characterSet);
                }
            }
        }

        public static byte[] SignInvisible(this Session session,
            Mechanism mechanism, ObjectHandle keyHandle, byte[] data)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var mechanism41 = new Net.Pkcs11Interop.HighLevelAPI41.Mechanism((uint)mechanism.Type);
                    var keyHandle41 = new Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle((uint)keyHandle.ObjectId);

                    return session.HLA41Session.SignInvisible(ref mechanism41, keyHandle41, data);
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
                    var mechanism81 = new Net.Pkcs11Interop.HighLevelAPI81.Mechanism((uint)mechanism.Type);
                    var keyHandle81 = new Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle((uint)keyHandle.ObjectId);

                    return session.HLA81Session.SignInvisible(ref mechanism81, keyHandle81, data);
                }
            }
        }

        public static string CreateCSR(this Session session, ObjectHandle publicKey,
            string[] dn, ObjectHandle privateKey,
            string[] attributes, string[] extensions)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var publicKeyHandle41 = new Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle((uint)publicKey.ObjectId);
                    var privateKeyHandle41 = new Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle((uint)privateKey.ObjectId);

                    return session.HLA41Session.CreateCSR(publicKeyHandle41, dn, privateKeyHandle41, attributes, extensions);
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
                    var publicKeyHandle81 = new Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle((uint)publicKey.ObjectId);
                    var privateKeyHandle81 = new Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle((uint)privateKey.ObjectId);

                    return session.HLA81Session.CreateCSR(publicKeyHandle81, dn, privateKeyHandle81, attributes, extensions);
                }
            }
        }

        public static string GetCertificateInfoText(this Session session, ObjectHandle certificate)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var certificateHandle41 = new Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle((uint)certificate.ObjectId);

                    return session.HLA41Session.GetCertificateInfoText(certificateHandle41);
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
                    var certificateHandle81 = new Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle((uint)certificate.ObjectId);

                    return session.HLA81Session.GetCertificateInfoText(certificateHandle81);
                }
            }
        }

        public static byte[] PKCS7Sign(this Session session, byte[] data, ObjectHandle certificate,
            ObjectHandle privateKey, uint[] certificates, uint flags)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var certificateHandle41 = new Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle((uint)certificate.ObjectId);
                    var privateKeyHandle41 = new Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle((uint)privateKey.ObjectId);

                    return session.HLA41Session.PKCS7Sign(data, certificateHandle41, privateKeyHandle41, certificates, flags);
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
                    var certificateHandle81 = new Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle((uint)certificate.ObjectId);
                    var privateKeyHandle81 = new Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle((uint)privateKey.ObjectId);

                    var certificates81 = certificates.Select(cert => (ulong) cert).ToArray();

                    return session.HLA81Session.PKCS7Sign(data, certificateHandle81, privateKeyHandle81, certificates81, flags);
                }
            }
        }

        public static Pkcs7VerificationResult PKCS7Verify(this Session session, byte[] cms,
            CkVendorX509Store vendorX509Store,
            VendorCrlMode mode, uint flags)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    return session.HLA41Session.PKCS7Verify(cms, vendorX509Store, mode, flags);
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

        public static void TokenManage(this Session session, TokenManageMode mode, byte[] value)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    session.HLA41Session.TokenManage(mode, value);
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
                    session.HLA81Session.TokenManage(mode, value);
                }
            }
        }

        public static byte[] ExtendedWrapKey(this Session session,
            Mechanism generationMechanism, List<ObjectAttribute> keyAttributes,
            Mechanism derivationMechanism, ObjectHandle baseKey,
            Mechanism wrappingMechanism, ref ObjectHandle key)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var generationMechanism41 =
                        generationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI41.Mechanism>("Mechanism41");
                    var derivationMechanism41 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI41.Mechanism>("Mechanism41");
                    var wrappingMechanism41 =
                        wrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI41.Mechanism>("Mechanism41");

                    List<Net.Pkcs11Interop.HighLevelAPI41.ObjectAttribute> keyAttributes41 =
                        (List<Net.Pkcs11Interop.HighLevelAPI41.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI41List",
                            keyAttributes);

                    var baseKeyHandle41 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle>("ObjectHandle41");

                    Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle keyHandle41 = null;

                    byte[] wrappedKey = session.HLA41Session.ExtendedWrapKey(generationMechanism41, keyAttributes41,
                        derivationMechanism41, baseKeyHandle41, wrappingMechanism41, ref keyHandle41);

                    key.SetPrivateFieldValue("_objectHandle41", keyHandle41);

                    return wrappedKey;
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
                    var generationMechanism81 =
                        generationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI81.Mechanism>("Mechanism81");
                    var derivationMechanism81 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI81.Mechanism>("Mechanism81");
                    var wrappingMechanism81 =
                        wrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI81.Mechanism>("Mechanism81");

                    List<Net.Pkcs11Interop.HighLevelAPI81.ObjectAttribute> keyAttributes81 =
                        (List<Net.Pkcs11Interop.HighLevelAPI81.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI81List",
                            keyAttributes);

                    var baseKeyHandle81 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle>("ObjectHandle81");

                    Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle keyHandle81 = null;

                    byte[] wrappedKey = session.HLA81Session.ExtendedWrapKey(generationMechanism81, keyAttributes81,
                        derivationMechanism81, baseKeyHandle81, wrappingMechanism81, ref keyHandle81);

                    key.SetPrivateFieldValue("_objectHandle81", keyHandle81);

                    return wrappedKey;
                }
            }
        }

        public static ObjectHandle ExtendedUnwrapKey(this Session session,
            Mechanism derivationMechanism, ObjectHandle baseKey,
            Mechanism unwrappingMechanism,
            byte[] wrappedKey, List<ObjectAttribute> keyAttributes)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var derivationMechanism41 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI41.Mechanism>("Mechanism41");
                    var unwrappingMechanism41 =
                        unwrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI41.Mechanism>("Mechanism41");

                    List<Net.Pkcs11Interop.HighLevelAPI41.ObjectAttribute> keyAttributes41 =
                        (List<Net.Pkcs11Interop.HighLevelAPI41.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI41List",
                            keyAttributes);

                    var baseKeyHandle41 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle>("ObjectHandle41");

                    Net.Pkcs11Interop.HighLevelAPI41.ObjectHandle keyHandle41 = session.HLA41Session.ExtendedUnwrapKey(derivationMechanism41, baseKeyHandle41,
                        unwrappingMechanism41, wrappedKey, keyAttributes41);

                    var keyHandle = new ObjectHandle();
                    keyHandle.SetPrivateFieldValue("_objectHandle41", keyHandle41);
                    return keyHandle;
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
                    var derivationMechanism81 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI81.Mechanism>("Mechanism81");
                    var unwrappingMechanism81 =
                        unwrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI81.Mechanism>("Mechanism81");

                    List<Net.Pkcs11Interop.HighLevelAPI81.ObjectAttribute> keyAttributes81 =
                        (List<Net.Pkcs11Interop.HighLevelAPI81.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI81List",
                            keyAttributes);

                    var baseKeyHandle81 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle>("ObjectHandle81");

                    Net.Pkcs11Interop.HighLevelAPI81.ObjectHandle keyHandle81 = session.HLA81Session.ExtendedUnwrapKey(derivationMechanism81, baseKeyHandle81,
                        unwrappingMechanism81, wrappedKey, keyAttributes81);

                    var keyHandle = new ObjectHandle();
                    keyHandle.SetPrivateFieldValue("_objectHandle81", keyHandle81);
                    return keyHandle;
                }
            }
        }
    }
}
