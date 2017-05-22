using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
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

        public static void LoacActivationKey(this Session session, byte[] key)
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
    }
}
