using System;
using System.Runtime.InteropServices;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI41;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI41
{
    [TestFixture()]
    public class _LL41_29_ManageFlashTest
    {
        /// <summary>
        /// Тест для проверки наличия флеш-памяти у токена
        /// </summary>
        [Test()]
        public void _LL41_29_01_FlashAvailabilityTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                // Получение расширенной информации о токене
                var tokenInfo = new CK_TOKEN_INFO_EXTENDED
                {
                    SizeofThisStructure = Convert.ToUInt32(Marshal.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)))
                };
                rv = pkcs11.C_EX_GetTokenInfoExtended(slotId, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверка флага доступности Flash
                var isFlashMemoryAvailable = tokenInfo.Flags & (uint)RutokenFlag.HasFlashDrive;
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
        public void _LL41_29_02_FlashWorkTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                // Получение расширенной информации о токене
                var tokenInfo = new CK_TOKEN_INFO_EXTENDED
                {
                    SizeofThisStructure = Convert.ToUInt32(Marshal.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)))
                };
                rv = pkcs11.C_EX_GetTokenInfoExtended(slotId, ref tokenInfo);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверка флага доступности Flash
                var isFlashMemoryAvailable = tokenInfo.Flags & (uint)RutokenFlag.HasFlashDrive;
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
                uint driveSize = 0;
                rv = pkcs11.C_EX_GetDriveSize(slotId, ref driveSize);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                Assert.IsTrue(driveSize > 0);

                // Полное удаление информации с флеш-памяти с последующим созданием
                // разделов в соответствии с переданными параметрами
                uint volumeRwSize = driveSize / 2;
                uint volumeRoSize = driveSize / 4;
                uint volumeHiSize = driveSize / 8;
                uint volumeCdSize = driveSize - volumeRwSize - volumeRoSize - volumeHiSize;

                var initParams = new CK_VOLUME_FORMAT_INFO_EXTENDED[4]
                {
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeRwSize, AccessMode = (uint) FlashAccessMode.Readwrite, VolumeOwner = (uint) CKU.CKU_USER, Flags = 0},
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeRoSize, AccessMode = (uint) FlashAccessMode.Readonly, VolumeOwner = (uint) CKU.CKU_SO, Flags = 0},
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeHiSize, AccessMode = (uint) FlashAccessMode.Hidden, VolumeOwner = Settings.LocalPinId1, Flags = 0},
                    new CK_VOLUME_FORMAT_INFO_EXTENDED() { VolumeSize = volumeCdSize, AccessMode = (uint) FlashAccessMode.Cdrom, VolumeOwner = Settings.LocalPinId2, Flags = 0},
                };

                rv = pkcs11.C_EX_FormatDrive(slotId, (uint)CKU.CKU_SO,
                    Settings.SecurityOfficerPinArray, initParams);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выделение памяти под информацию о разделах флеш-памяти
                uint volumesInfoCount = 0;
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
                uint volumeRo = 2;
                rv = pkcs11.C_EX_ChangeVolumeAttributes(slotId, (uint)CKU.CKU_SO,
                    Settings.SecurityOfficerPinArray,
                    volumeRo, FlashAccessMode.Readwrite, permanent: true);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Временно изменить атрибут доступа к разделу флеш-памяти
                // (до первого извлечения устройства или следующего изменения атрибутов)
                uint volumeRw = 1;
                rv = pkcs11.C_EX_ChangeVolumeAttributes(slotId, (uint)CKU.CKU_USER,
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
