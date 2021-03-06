﻿using System;
using System.Runtime.InteropServices;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI80;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI80;

namespace RutokenPkcs11InteropTests.LowLevelAPI80
{
    [TestFixture()]
    public class _LL80_29_ManageFlashTest
    {
        /// <summary>
        /// Тест для проверки наличия флеш-памяти у токена
        /// </summary>
        [Test()]
        public void _LL80_29_01_FlashAvailabilityTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs80);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                // Получение расширенной информации о токене
                var tokenInfo = new CK_TOKEN_INFO_EXTENDED
                {
                    SizeofThisStructure = Convert.ToUInt64(Marshal.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)))
                };
                rv = pkcs11.C_EX_GetTokenInfoExtended(slotId, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверка флага доступности Flash
                var isFlashMemoryAvailable = tokenInfo.Flags & (ulong)RutokenFlag.HasFlashDrive;
                Assert.IsTrue(Convert.ToBoolean(isFlashMemoryAvailable));

                // Завершение сессии работы с библиотекой
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// Тест для проверки различных действий
        /// по работе с флеш-памятью токена
        /// </summary>
        [Test()]
        public void _LL80_29_02_FlashWorkTest()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs80);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                ulong slotId = Helpers.GetUsableSlot(pkcs11);

                // Получение расширенной информации о токене
                var tokenInfo = new CK_TOKEN_INFO_EXTENDED
                {
                    SizeofThisStructure = Convert.ToUInt64(Marshal.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)))
                };
                rv = pkcs11.C_EX_GetTokenInfoExtended(slotId, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверка флага доступности Flash
                var isFlashMemoryAvailable = tokenInfo.Flags & (ulong)RutokenFlag.HasFlashDrive;
                Assert.IsTrue(Convert.ToBoolean(isFlashMemoryAvailable));

                // Создание локальных PIN-кодов
                // (создание успешно только в случае их отсутствия)

                // Создание локального PIN-кода токена с ID = 0x03
                rv = pkcs11.C_EX_SetLocalPIN(slotId, Settings.NormalUserPinArray,
                    Settings.LocalPinArray, Settings.LocalPinId1);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Создание локального PIN-кода токена с ID = 0x1E
                rv = pkcs11.C_EX_SetLocalPIN(slotId, Settings.NormalUserPinArray,
                    Settings.LocalPinArray, Settings.LocalPinId2);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Получение объема флеш-памяти
                ulong driveSize = 0;
                rv = pkcs11.C_EX_GetDriveSize(slotId, ref driveSize);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                Assert.IsTrue(driveSize > 0);

                // Полное удаление информации с флеш-памяти с последующим созданием
                // разделов в соответствии с переданными параметрами
                ulong volumeRwSize = driveSize / 2;
                ulong volumeRoSize = driveSize / 4;
                ulong volumeHiSize = driveSize / 8;
                ulong volumeCdSize = driveSize - volumeRwSize - volumeRoSize - volumeHiSize;

                var initParams = new CK_VOLUME_FORMAT_INFO_EXTENDED[4]
                {
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeRwSize, AccessMode = (ulong) FlashAccessMode.Readwrite, VolumeOwner = (ulong) CKU.CKU_USER, Flags = 0},
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeRoSize, AccessMode = (ulong) FlashAccessMode.Readonly, VolumeOwner = (ulong) CKU.CKU_SO, Flags = 0},
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeHiSize, AccessMode = (ulong) FlashAccessMode.Hidden, VolumeOwner = Settings.LocalPinId1, Flags = 0},
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeCdSize, AccessMode = (ulong) FlashAccessMode.Cdrom, VolumeOwner = Settings.LocalPinId2, Flags = 0},
                };

                rv = pkcs11.C_EX_FormatDrive(slotId, (ulong)CKU.CKU_SO,
                    Settings.SecurityOfficerPinArray, initParams);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выделение памяти под информацию о разделах флеш-памяти
                ulong volumesInfoCount = 0;
                rv = pkcs11.C_EX_GetVolumesInfo(slotId, null, ref volumesInfoCount);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                Assert.IsTrue(volumesInfoCount > 0);
                var volumesInfo = new CK_VOLUME_INFO_EXTENDED[volumesInfoCount];

                // Получение информации о разделах флеш-памяти
                rv = pkcs11.C_EX_GetVolumesInfo(slotId, volumesInfo, ref volumesInfoCount);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                foreach (var volumeInfo in volumesInfo)
                {
                    Assert.IsTrue(volumeInfo.VolumeId != 0);
                }

                // Изменение атрибута доступа раздела флеш-памяти на постоянной основе
                // (до следующего изменения атрибутов)
                ulong volumeRo = 2;
                rv = pkcs11.C_EX_ChangeVolumeAttributes(slotId, (ulong)CKU.CKU_SO,
                    Settings.SecurityOfficerPinArray,
                    volumeRo, FlashAccessMode.Readwrite, permanent: true);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Временно изменить атрибут доступа к разделу флеш-памяти
                // (до первого извлечения устройства или следующего изменения атрибутов)
                ulong volumeRw = 1;
                rv = pkcs11.C_EX_ChangeVolumeAttributes(slotId, (ulong)CKU.CKU_USER,
                    Settings.NormalUserPinArray,
                    volumeRw, FlashAccessMode.Hidden, permanent: false);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии работы с библиотекой
                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
