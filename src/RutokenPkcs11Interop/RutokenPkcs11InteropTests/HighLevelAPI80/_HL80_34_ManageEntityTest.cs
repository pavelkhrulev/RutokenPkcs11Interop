using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI80;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI80;

namespace RutokenPkcs11InteropTests.HighLevelAPI80
{
    [TestFixture()]
    public class _HL80_34_ManageEntityTest
    {
        [Test()]
        public void _HL80_34_01_ManageSlotTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
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

        [Test()]
        public void _HL80_34_02_ManageTokenTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
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
