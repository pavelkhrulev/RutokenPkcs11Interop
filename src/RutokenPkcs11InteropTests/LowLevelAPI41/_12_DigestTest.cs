using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using NUnit.Framework;
using RutokenPkcs11Interop;

namespace RutokenPkcs11InteropTests.LowLevelAPI41
{
    /// <summary>
    /// C_DigestInit, C_Digest, C_DigestUpdate, C_DigestFinal and C_DigestKey tests.
    /// </summary>
    [TestFixture()]
    class _12_DigestTest
    {
        /// <summary>
        /// C_DigestInit and C_Digest test.
        /// </summary>
        [Test()]
        public void _12_01_Digest_SHA1_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                uint session = CK.CK_INVALID_HANDLE;
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
                uint digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), digest, ref digestLen);
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
        public void _12_02_Digest_Gost3411_12_512_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify digesting mechanism (needs no parameter => no unamanaged memory is needed)
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                // Initialize digesting operation
                rv = pkcs11.C_DigestInit(session, ref mechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData =
                {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                };

                // Get length of digest value in first call
                uint digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] targetData =
                {
                    0xDA, 0x8E, 0xC0, 0xC1, 0xD7, 0x65, 0x7E, 0x8F,
                    0xA4, 0xD6, 0xD0, 0x72, 0x5E, 0xCC, 0x39, 0x7A,
                    0x0F, 0x92, 0x85, 0xD2, 0x67, 0x24, 0xA4, 0xDE,
                    0x7B, 0x60, 0x92, 0xEE, 0x28, 0xE5, 0xA6, 0x9D,
                    0x99, 0x99, 0x1C, 0x55, 0xC9, 0xB4, 0x38, 0x9F,
                    0x68, 0x41, 0xA0, 0xD6, 0x75, 0xD9, 0xBD, 0x29,
                    0x6A, 0x3C, 0x79, 0x4E, 0x70, 0xC0, 0xDE, 0x07,
                    0x55, 0x7F, 0x8D, 0x5F, 0x63, 0x7C, 0x05, 0x13,
                };

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
        public void _12_03_Digest_Gost3411_12_256_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify digesting mechanism (needs no parameter => no unamanaged memory is needed)
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3411_12_256);

                // Initialize digesting operation
                rv = pkcs11.C_DigestInit(session, ref mechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData =
                {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                };

                // Get length of digest value in first call
                uint digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] targetData =
                {
                    0x8B, 0xD8, 0x27, 0xAE, 0xB4, 0x5C, 0xB4, 0x64,
                    0x5D, 0x2D, 0x3F, 0x4B, 0xDF, 0xE2, 0xF8, 0x51,
                    0x78, 0x9C, 0x4A, 0xD4, 0xFD, 0x72, 0x3E, 0xFE,
                    0x23, 0xA3, 0x63, 0x0B, 0x66, 0x8B, 0xDA, 0x33
                };

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
        public void _12_04_Digest_Gost3411_94_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Specify digesting mechanism (needs no parameter => no unamanaged memory is needed)
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3411);

                // Initialize digesting operation
                rv = pkcs11.C_DigestInit(session, ref mechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData =
                {
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                };

                // Get length of digest value in first call
                uint digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Allocate array for digest value
                byte[] digest = new byte[digestLen];

                // Get digest value in second call
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] targetData =
                {
                    0x82, 0xCD, 0x06, 0xFE, 0x34, 0x14, 0x5B, 0x0B,
                    0x1D, 0x07, 0x7D, 0x3B, 0x71, 0xB2, 0x3B, 0x85,
                    0x9F, 0x78, 0xA6, 0x53, 0x0D, 0xB6, 0x6D, 0x6A,
                    0x34, 0x4C, 0xA6, 0x5E, 0x7F, 0x58, 0x26, 0xEC
                };

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
