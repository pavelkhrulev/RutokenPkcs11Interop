using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using NUnit.Framework;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI81;

namespace RutokenPkcs11InteropTests.LowLevelAPI81
{
    /// <summary>
    /// C_DigestInit, C_Digest, C_DigestUpdate, C_DigestFinal and C_DigestKey tests.
    /// </summary>
    [TestFixture()]
    public class _LL81_12_DigestTest
    {
        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _LL81_12_01_Digest_SHA1_Test()
        {
            if (Platform.NativeULongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                ulong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify digesting mechanism (needs no parameter => no unamanaged memory is needed)
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_SHA_1);

                // Initialize digesting operation
                rv = pkcs11.C_DigestInit(session, ref mechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = ConvertUtils.Utf8StringToBytes("Hello world");

                // Get length of digest value in first call
                ulong digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Do something interesting with digest value

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _LL81_12_02_Digest_Gost3411_12_512_Test()
        {
            if (Platform.NativeULongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                ulong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify digesting mechanism (needs no parameter => no unamanaged memory is needed)
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3411_12_512);

                // Initialize digesting operation
                rv = pkcs11.C_DigestInit(session, ref mechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                // Get length of digest value in first call
                ulong digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] targetData = TestData.Digest_Gost3411_12_512_TargetData;

                // Do something interesting with digest value
                Assert.IsTrue(Convert.ToBase64String(digest) == Convert.ToBase64String(targetData));

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _LL81_12_03_Digest_Gost3411_12_256_Test()
        {
            if (Platform.NativeULongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                ulong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify digesting mechanism (needs no parameter => no unamanaged memory is needed)
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3411_12_256);

                // Initialize digesting operation
                rv = pkcs11.C_DigestInit(session, ref mechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                // Get length of digest value in first call
                ulong digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] targetData = TestData.Digest_Gost3411_12_256_TargetData;

                // Do something interesting with digest value
                Assert.IsTrue(Convert.ToBase64String(digest) == Convert.ToBase64String(targetData));

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _LL81_12_04_Digest_Gost3411_94_Test()
        {
            if (Platform.NativeULongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs81);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                ulong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify digesting mechanism (needs no parameter => no unamanaged memory is needed)
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_GOSTR3411);

                // Initialize digesting operation
                rv = pkcs11.C_DigestInit(session, ref mechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                // Get length of digest value in first call
                ulong digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] targetData = TestData.Digest_Gost3411_94_TargetData;

                Assert.IsTrue(Convert.ToBase64String(digest) == Convert.ToBase64String(targetData));

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
