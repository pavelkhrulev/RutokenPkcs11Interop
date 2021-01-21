using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI80;
using NUnit.Framework;
using Net.RutokenPkcs11Interop.LowLevelAPI80;

using NativeULong = System.UInt64;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI80
{
    /// <summary>
    /// C_GetInfo tests.
    /// </summary>
    [TestFixture()]
    public class _LL_02_GetInfoTest
    {
        /// <summary>
        /// Basic C_GetInfo test.
        /// </summary>
        [Test()]
        public void _LL_02_01_BasicGetInfoTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs80);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                CK_INFO info = new CK_INFO();
                rv = pkcs11.C_GetInfo(ref info);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // TODO: можно сделать проверки на версию нативной библиотеки
                Assert.IsFalse(String.IsNullOrEmpty(ConvertUtils.BytesToUtf8String(info.ManufacturerId)));

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
