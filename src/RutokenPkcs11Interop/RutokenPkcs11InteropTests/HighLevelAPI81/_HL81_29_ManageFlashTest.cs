using System;
using System.Collections.Generic;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI81;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI81;

namespace RutokenPkcs11InteropTests.HighLevelAPI81
{
    [TestFixture()]
    public class _HL81_29_ManageFlashTest
    {
        /// <summary>
        /// Тест для проверки наличия флеш-памяти у токена
        /// </summary>
        [Test()]
        public void _HL81_29_01_FlashAvailabilityTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                var tokenInfo = slot.GetTokenInfoExtended();

                var isFlashMemoryAvailable = tokenInfo.Flags & (ulong)RutokenFlag.HasFlashDrive;
                Assert.IsTrue(Convert.ToBoolean(isFlashMemoryAvailable));
            }
        }

        /// <summary>
        /// Тест для проверки различных действий
        /// по работе с флеш-памятью токена
        /// </summary>
        [Test()]
        public void _HL81_29_02_FlashWorkTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                var tokenInfo = slot.GetTokenInfoExtended();

                var isFlashMemoryAvailable = tokenInfo.Flags & (ulong)RutokenFlag.HasFlashDrive;
                Assert.IsTrue(Convert.ToBoolean(isFlashMemoryAvailable));

                // Создание локальных PIN-кодов
                // (создание успешно только в случае их отсутствия)

                // Создание локального PIN-кода токена с ID = 0x03
                slot.SetLocalPIN(Settings.NormalUserPin, Settings.LocalPin, Settings.LocalPinId1);

                // Создание локального PIN-кода токена с ID = 0x1E
                slot.SetLocalPIN(Settings.NormalUserPin, Settings.LocalPin, Settings.LocalPinId2);

                // Получение объема флеш-памяти
                var driveSize = slot.GetDriveSize();
                Assert.IsTrue(driveSize > 0);

                // Полное удаление информации с флеш-памяти с последующим созданием
                // разделов в соответствии с переданными параметрами
                ulong volumeRwSize = driveSize / 2;
                ulong volumeRoSize = driveSize / 4;
                ulong volumeHiSize = driveSize / 8;
                ulong volumeCdSize = driveSize - volumeRwSize - volumeRoSize - volumeHiSize;

                var initParams = new List<VolumeFormatInfoExtended>()
                {
                    new VolumeFormatInfoExtended(volumeRwSize, FlashAccessMode.Readwrite, CKU.CKU_USER, 0),
                    new VolumeFormatInfoExtended(volumeRoSize, FlashAccessMode.Readonly, CKU.CKU_SO, 0),
                    new VolumeFormatInfoExtended(volumeHiSize, FlashAccessMode.Hidden, (CKU)Settings.LocalPinId1, 0),
                    new VolumeFormatInfoExtended(volumeCdSize, FlashAccessMode.Cdrom, (CKU)Settings.LocalPinId2, 0),
                };

                slot.FormatDrive(CKU.CKU_SO, Settings.SecurityOfficerPin, initParams);

                // Получение информации о разделах флеш-памяти
                var volumesInfo = slot.GetVolumesInfo();
                foreach (var volumeInfo in volumesInfo)
                {
                    Assert.IsTrue(volumeInfo.VolumeId != 0);
                }

                // Изменение атрибута доступа раздела флеш-памяти на постоянной основе
                // (до следующего изменения атрибутов)
                ulong volumeRo = 2;
                slot.ChangeVolumeAttributes(CKU.CKU_SO, Settings.SecurityOfficerPin,
                    volumeRo, FlashAccessMode.Readwrite, permanent: true);

                // Временно изменить атрибут доступа к разделу флеш-памяти
                // (до первого извлечения устройства или следующего изменения атрибутов)
                ulong volumeRw = 1;
                slot.ChangeVolumeAttributes(CKU.CKU_USER, Settings.NormalUserPin,
                    volumeRw, FlashAccessMode.Hidden, permanent: false);
            }
        }
    }
}
