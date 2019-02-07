using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI81;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI81;

namespace RutokenPkcs11InteropTests.HighLevelAPI81
{
    [TestClass]
    public class _HL81_34_ManageEntityTest
    {
        [TestMethod]
        public void _HL81_34_01_ManageSlotTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // TODO: актуализировать тест с реальными значениями
                ulong mode = 0x00;
                byte[] value = new byte[8];
                slot.SlotManage(mode, value);
            }
        }

        [TestMethod]
        public void _HL81_34_02_ManageTokenTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // TODO: актуализировать тест с реальными значениями
                    byte[] value = new byte[8];
                    session.TokenManage(TokenManageMode.BluetoothPoweroffTimeoutDefault, value);
                }
            }
        }
    }
}
