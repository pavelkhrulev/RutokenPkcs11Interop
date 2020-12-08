using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.Helpers;
using RutokenPkcs11Interop.HighLevelAPI40;
using RutokenPkcs11Interop.HighLevelAPI41;
using RutokenPkcs11Interop.HighLevelAPI80;
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
                    session.HLA40Session.UnblockUserPIN();
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
                    session.HLA80Session.UnblockUserPIN();
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
                    session.HLA40Session.SetTokenName(label);
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
                    session.HLA80Session.SetTokenName(label);
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
                    return session.HLA40Session.GetTokenLabel();
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
                    return session.HLA80Session.GetTokenLabel();
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
                    session.HLA40Session.SetLicense(licenseNum, license);
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
                    session.HLA80Session.SetLicense(licenseNum, license);
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
                    return session.HLA40Session.GetLicense(licenseNum);
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
                    return session.HLA80Session.GetLicense(licenseNum);
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
                    session.HLA40Session.LoadActivationKey(key);
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
                    session.HLA80Session.LoadActivationKey(key);
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
                    return session.HLA40Session.GenerateActivationPassword(passwordNumber, characterSet);
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
                    return session.HLA80Session.GenerateActivationPassword(passwordNumber, characterSet);
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
                    var mechanism40 = new Net.Pkcs11Interop.HighLevelAPI40.Mechanism((uint)mechanism.Type);
                    var keyHandle40 = new Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle((uint)keyHandle.ObjectId);

                    return session.HLA40Session.SignInvisible(ref mechanism40, keyHandle40, data);
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
                    var mechanism80 = new Net.Pkcs11Interop.HighLevelAPI80.Mechanism((uint)mechanism.Type);
                    var keyHandle80 = new Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle((uint)keyHandle.ObjectId);

                    return session.HLA80Session.SignInvisible(ref mechanism80, keyHandle80, data);
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
                    var publicKeyHandle40 = new Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle((uint)publicKey.ObjectId);
                    var privateKeyHandle40 = new Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle((uint)privateKey.ObjectId);

                    return session.HLA40Session.CreateCSR(publicKeyHandle40, dn, privateKeyHandle40, attributes, extensions);
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
                    var publicKeyHandle80 = new Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle((uint)publicKey.ObjectId);
                    var privateKeyHandle80 = new Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle((uint)privateKey.ObjectId);

                    return session.HLA80Session.CreateCSR(publicKeyHandle80, dn, privateKeyHandle80, attributes, extensions);
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
                    var certificateHandle40 = new Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle((uint)certificate.ObjectId);

                    return session.HLA40Session.GetCertificateInfoText(certificateHandle40);
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
                    var certificateHandle80 = new Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle((uint)certificate.ObjectId);

                    return session.HLA80Session.GetCertificateInfoText(certificateHandle80);
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
                    var certificateHandle40 = new Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle((uint)certificate.ObjectId);
                    var privateKeyHandle40 = new Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle((uint)privateKey.ObjectId);

                    return session.HLA40Session.PKCS7Sign(data, certificateHandle40, privateKeyHandle40, certificates, flags);
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
                    var certificateHandle80 = new Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle((uint)certificate.ObjectId);
                    var privateKeyHandle80 = new Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle((uint)privateKey.ObjectId);

                    var certificates80 = certificates.Select(cert => (ulong)cert).ToArray();

                    return session.HLA80Session.PKCS7Sign(data, certificateHandle80, privateKeyHandle80, certificates80, flags);
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
                    return session.HLA40Session.PKCS7Verify(cms, vendorX509Store, mode, flags);
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
                    return session.HLA80Session.PKCS7Verify(cms, vendorX509Store, mode, flags);
                }
                else
                {
                    return session.HLA81Session.PKCS7Verify(cms, vendorX509Store, mode, flags);
                }
            }
        }

        public static Pkcs7VerificationResult PKCS7Verify(this Session session, byte[] cms,
            Stream inputStream,
            CkVendorX509Store vendorX509Store,
            VendorCrlMode mode, uint flags)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    return session.HLA40Session.PKCS7Verify(cms, inputStream, vendorX509Store, mode, flags);
                }
                else
                {
                    return session.HLA41Session.PKCS7Verify(cms, inputStream, vendorX509Store, mode, flags);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    return session.HLA80Session.PKCS7Verify(cms, inputStream, vendorX509Store, mode, flags);
                }
                else
                {
                    return session.HLA81Session.PKCS7Verify(cms, inputStream, vendorX509Store, mode, flags);
                }
            }
        }

        public static void TokenManage(this Session session, TokenManageMode mode, byte[] value)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    session.HLA40Session.TokenManage(mode, value);
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
                    session.HLA80Session.TokenManage(mode, value);
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
                    var generationMechanism40 =
                        generationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI40.Mechanism>("Mechanism40");
                    var derivationMechanism40 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI40.Mechanism>("Mechanism40");
                    var wrappingMechanism40 =
                        wrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI40.Mechanism>("Mechanism40");

                    List<Net.Pkcs11Interop.HighLevelAPI40.ObjectAttribute> keyAttributes40 =
                        (List<Net.Pkcs11Interop.HighLevelAPI40.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI40List",
                            keyAttributes);

                    var baseKeyHandle40 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle>("ObjectHandle40");

                    Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle keyHandle40 = null;

                    byte[] wrappedKey = session.HLA40Session.ExtendedWrapKey(generationMechanism40, keyAttributes40,
                        derivationMechanism40, baseKeyHandle40, wrappingMechanism40, ref keyHandle40);

                    key.SetPrivateFieldValue("_objectHandle40", keyHandle40);

                    return wrappedKey;
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
                    var generationMechanism80 =
                        generationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI80.Mechanism>("Mechanism80");
                    var derivationMechanism80 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI80.Mechanism>("Mechanism80");
                    var wrappingMechanism80 =
                        wrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI80.Mechanism>("Mechanism80");

                    List<Net.Pkcs11Interop.HighLevelAPI80.ObjectAttribute> keyAttributes80 =
                        (List<Net.Pkcs11Interop.HighLevelAPI80.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI80List",
                            keyAttributes);

                    var baseKeyHandle80 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle>("ObjectHandle80");

                    Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle keyHandle80 = null;

                    byte[] wrappedKey = session.HLA80Session.ExtendedWrapKey(generationMechanism80, keyAttributes80,
                        derivationMechanism80, baseKeyHandle80, wrappingMechanism80, ref keyHandle80);

                    key.SetPrivateFieldValue("_objectHandle80", keyHandle80);

                    return wrappedKey;
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
                    var derivationMechanism40 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI40.Mechanism>("Mechanism40");
                    var unwrappingMechanism40 =
                        unwrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI40.Mechanism>("Mechanism40");

                    List<Net.Pkcs11Interop.HighLevelAPI40.ObjectAttribute> keyAttributes40 =
                        (List<Net.Pkcs11Interop.HighLevelAPI40.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI40List",
                            keyAttributes);

                    var baseKeyHandle40 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle>("ObjectHandle40");

                    Net.Pkcs11Interop.HighLevelAPI40.ObjectHandle keyHandle40 = session.HLA40Session.ExtendedUnwrapKey(derivationMechanism40, baseKeyHandle40,
                        unwrappingMechanism40, wrappedKey, keyAttributes40);

                    var keyHandle = new ObjectHandle();
                    keyHandle.SetPrivateFieldValue("_objectHandle40", keyHandle40);
                    return keyHandle;
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
                    var derivationMechanism80 =
                        derivationMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI80.Mechanism>("Mechanism80");
                    var unwrappingMechanism80 =
                        unwrappingMechanism.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI80.Mechanism>("Mechanism80");

                    List<Net.Pkcs11Interop.HighLevelAPI80.ObjectAttribute> keyAttributes80 =
                        (List<Net.Pkcs11Interop.HighLevelAPI80.ObjectAttribute>)
                        ReflectionHelper.CallInternalStaticMethod(typeof(ObjectAttribute), "ConvertToHighLevelAPI80List",
                            keyAttributes);

                    var baseKeyHandle80 =
                        baseKey.GetPrivatePropertyValue<Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle>("ObjectHandle80");

                    Net.Pkcs11Interop.HighLevelAPI80.ObjectHandle keyHandle80 = session.HLA80Session.ExtendedUnwrapKey(derivationMechanism80, baseKeyHandle80,
                        unwrappingMechanism80, wrappedKey, keyAttributes80);

                    var keyHandle = new ObjectHandle();
                    keyHandle.SetPrivateFieldValue("_objectHandle80", keyHandle80);
                    return keyHandle;
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

        public static PinPolicy GetPinPolicy(this Session session, CKU userType)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    return session.HLA40Session.GetPinPolicy(userType);
                }
                else
                {
                    return session.HLA41Session.GetPinPolicy(userType);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    return session.HLA80Session.GetPinPolicy(userType);
                }
                else
                {
                    return session.HLA81Session.GetPinPolicy(userType);
                }
            }
        }

        public static void SetPinPolicy(this Session session, PinPolicy pinPolicy, CKU userType)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    session.HLA40Session.SetPinPolicy(pinPolicy, userType);
                }
                else
                {
                    session.HLA41Session.SetPinPolicy(pinPolicy, userType);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    session.HLA80Session.SetPinPolicy(pinPolicy, userType);
                }
                else
                {
                    session.HLA81Session.SetPinPolicy(pinPolicy, userType);
                }
            }
        }

        public static bool PinPolicySupports(this Session session, CKU userType)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    return session.HLA40Session.PinPolicySupports(userType);
                }
                else
                {
                    return session.HLA41Session.PinPolicySupports(userType);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    return session.HLA80Session.PinPolicySupports(userType);
                }
                else
                {
                    return session.HLA81Session.PinPolicySupports(userType);
                }
            }
        }
    }
}
