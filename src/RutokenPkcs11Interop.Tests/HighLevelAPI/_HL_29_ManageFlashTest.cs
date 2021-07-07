﻿using System;
using System.Collections.Generic;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_29_ManageFlashTest
    {
        [Test()]
        public void _HL_29_01_FlashAvailabilityTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                var tokenInfo = slot.GetTokenInfoExtended();

                var isFlashMemoryAvailable = tokenInfo.Flags & (uint)RutokenFlag.HasFlashDrive;
                Assert.IsTrue(Convert.ToBoolean(isFlashMemoryAvailable));
            }
        }

        /// <summary>
        /// Тест для проверки различных действий
        /// по работе с флеш-памятью токена
        /// </summary>
        [Test()]
        public void _HL_29_02_FlashWorkTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                var tokenInfo = slot.GetTokenInfoExtended();

                var isFlashMemoryAvailable = tokenInfo.Flags & (uint)RutokenFlag.HasFlashDrive;
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

                var initParams = new List<IVolumeFormatInfoExtended>()
                {
                    Settings.Factories.VolumeFormatInfoExtendedFactory.Create(volumeRwSize, FlashAccessMode.Readwrite, CKU.CKU_USER, 0),
                    Settings.Factories.VolumeFormatInfoExtendedFactory.Create(volumeRoSize, FlashAccessMode.Readonly, CKU.CKU_SO, 0),
                    Settings.Factories.VolumeFormatInfoExtendedFactory.Create(volumeHiSize, FlashAccessMode.Hidden, (CKU)Settings.LocalPinId1, 0),
                    Settings.Factories.VolumeFormatInfoExtendedFactory.Create(volumeCdSize, FlashAccessMode.Cdrom, (CKU)Settings.LocalPinId2, 0),
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
                uint volumeRo = 2;
                slot.ChangeVolumeAttributes(CKU.CKU_SO, Settings.SecurityOfficerPin,
                    volumeRo, FlashAccessMode.Readwrite, permanent: true);

                // Временно изменить атрибут доступа к разделу флеш-памяти
                // (до первого извлечения устройства или следующего изменения атрибутов)
                uint volumeRw = 1;
                slot.ChangeVolumeAttributes(CKU.CKU_USER, Settings.NormalUserPin,
                    volumeRw, FlashAccessMode.Hidden, permanent: false);
            }
        }
    }
}
