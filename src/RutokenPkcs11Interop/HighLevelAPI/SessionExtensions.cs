using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.HighLevelAPI41;

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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
                }
            }
        }
    }
}
