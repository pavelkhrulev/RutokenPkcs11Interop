using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestClass]
    public class _HL_34_ManageEntityTest
    {
        [TestMethod]
        public void _HL_34_01_ManageSlotTest()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // TODO: актуализировать тест с реальными значениями
                uint mode = 0x00;
                byte[] value = new byte[8];
                slot.SlotManage(mode, value);
            }
        }

        [TestMethod]
        public void _HL_34_02_ManageTokenTest()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
                {
                    // TODO: актуализировать тест с реальными значениями
                    byte[] value = new byte[8];
                    session.TokenManage(TokenManageMode.BluetoothPoweroffTimeoutDefault, value);
                }
            }
        }
    }
}
