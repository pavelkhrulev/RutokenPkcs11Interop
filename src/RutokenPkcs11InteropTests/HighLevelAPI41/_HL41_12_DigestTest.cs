using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI41;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11InteropTests.HighLevelAPI41
{
    /// <summary>
    /// C_DigestInit, C_Digest, C_DigestUpdate, C_DigestFinal and C_DigestKey tests.
    /// </summary>
    [TestClass]
    public class _12_DigestTest
    {
        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [TestMethod]
        public void _HL41_12_01_Digest_SHA1_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism(CKM.CKM_SHA_1);

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
        [TestMethod]
        public void _HL41_12_02_Digest_Gost3411_12_512_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

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
        [TestMethod]
        public void _HL41_12_03_Digest_Gost3411_12_256_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_256);

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
        [TestMethod]
        public void _HL41_12_04_Digest_Gost3411_94_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Find first slot with token present
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RO session
                using (Session session = slot.OpenSession(true))
                {
                    // Specify digesting mechanism
                    Mechanism mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411);

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
