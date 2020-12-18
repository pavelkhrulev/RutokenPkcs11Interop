using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_34_ManageEntityTest
    {
        [Test()]
        public void _HL_34_01_ManageSlotTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // TODO: актуализировать тест с реальными значениями
                uint mode = 0x00;
                byte[] value = new byte[8];
                slot.SlotManage(mode, value);
            }
        }

        [Test()]
        public void _HL_34_02_ManageTokenTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    // TODO: актуализировать тест с реальными значениями
                    byte[] value = new byte[8];
                    session.TokenManage(TokenManageMode.BluetoothPoweroffTimeoutDefault, value);
                }
            }
        }
    }
}
