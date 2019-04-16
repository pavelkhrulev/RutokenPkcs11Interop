using System;
using Net.Pkcs11Interop.Common;
using NUnit.Framework;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    /// <summary>
    /// C_DigestInit, C_Digest, C_DigestUpdate, C_DigestFinal and C_DigestKey tests.
    /// </summary>
    [TestFixture()]
    public class _HL_12_DigestTest
    {
        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _HL_12_01_Digest_SHA1_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(SessionType.ReadOnly))
                {
                    // Specify digesting mechanism
                    var mechanism = new Mechanism(CKM.CKM_SHA_1);

                    byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");

                    // Digest data
                    byte[] digest = session.Digest(mechanism, sourceData);

                    // Do something interesting with digest value
                    Assert.IsTrue(Convert.ToBase64String(digest) == "e1AsOh9IyGCa4hLN+2Od7jlnP14=");
                }
            }
        }

        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _HL_12_02_Digest_Gost3411_12_512_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find firsst slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(SessionType.ReadOnly))
                {
                    // Specify digesting mechanism
                    var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Digest data
                    byte[] digest = session.Digest(mechanism, sourceData);

                    byte[] targetData = TestData.Digest_Gost3411_12_512_TargetData;

                    // Do something interesting with digest value
                    Assert.IsTrue(Convert.ToBase64String(digest) == Convert.ToBase64String(targetData));
                }
            }
        }

        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _HL_12_03_Digest_Gost3411_12_256_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(SessionType.ReadOnly))
                {
                    // Specify digesting mechanism
                    var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_256);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Digest data
                    byte[] digest = session.Digest(mechanism, sourceData);

                    byte[] targetData = TestData.Digest_Gost3411_12_256_TargetData;

                    Assert.IsTrue(Convert.ToBase64String(digest) == Convert.ToBase64String(targetData));
                }
            }
        }

        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _HL_12_04_Digest_Gost3411_94_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(SessionType.ReadOnly))
                {
                    // Specify digesting mechanism
                    var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Digest data
                    byte[] digest = session.Digest(mechanism, sourceData);

                    byte[] targetData = TestData.Digest_Gost3411_94_TargetData;

                    Assert.IsTrue(Convert.ToBase64String(digest) == Convert.ToBase64String(targetData));
                }
            }
        }
    }
}
