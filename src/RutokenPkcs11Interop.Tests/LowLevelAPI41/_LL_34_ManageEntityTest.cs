using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI41;

using NativeULong = System.UInt32;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI41
{
    [TestFixture()]
    public class _LL_34_ManageEntityTest
    {
        [Test()]
        public void _LL_34_01_ManageSlotTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // TODO: актуализировать тест с реальными значениями

                rv = pkcs11.C_EX_SlotManage(slotId, 0, IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        [Test()]
        public void _LL_34_02_ManageTokenTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (var pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero,
                    IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // TODO: актуализировать тест с реальными значениями

                rv = pkcs11.C_EX_TokenManage(session, (NativeULong)TokenManageMode.ChannelTypeBluetooth, IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии
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
