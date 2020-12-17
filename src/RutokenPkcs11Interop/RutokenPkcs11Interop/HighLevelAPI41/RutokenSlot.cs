using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI41;
using HLA41 = Net.Pkcs11Interop.HighLevelAPI41;

namespace RutokenPkcs11Interop.HighLevelAPI41
{
    public static class RutokenSlot
    {
        public static TokenInfoExtended GetTokenInfoExtended(this HLA41.Slot slot)
        {
            var tokenInfo = new CK_TOKEN_INFO_EXTENDED
            {
                SizeofThisStructure = Convert.ToUInt32(Marshal.SizeOf(typeof(CK_TOKEN_INFO_EXTENDED)))
            };

            CKR rv = slot.LowLevelPkcs11.C_EX_GetTokenInfoExtended(slot.SlotId, ref tokenInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetTokenInfoExtended", rv);

            return new TokenInfoExtended(tokenInfo);
        }

        public static void InitTokenExtended(this HLA41.Slot slot, string pin, RutokenInitParam initParam)
        {
            if (pin == null)
                throw new ArgumentNullException(nameof(pin));

            if (initParam == null)
                throw new ArgumentNullException(nameof(initParam));

            CK_RUTOKEN_INIT_PARAM ckInitParam = initParam.CkRutokenInitParam;

            byte[] pinArray = ConvertUtils.Utf8StringToBytes(pin);
            CKR rv = slot.LowLevelPkcs11.C_EX_InitToken(slot.SlotId, pinArray, ref ckInitParam);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_InitToken", rv);
        }

        public static byte[] GetJournal(this HLA41.Slot slot)
        {
            uint journalLength = 0;
            CKR rv = slot.LowLevelPkcs11.C_EX_GetJournal(slot.SlotId, null, ref journalLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetJournal", rv);

            byte[] journal = new byte[journalLength];

            rv = slot.LowLevelPkcs11.C_EX_GetJournal(slot.SlotId, journal, ref journalLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetJournal", rv);

            return journal;
        }

        public static void SetLocalPIN(this HLA41.Slot slot, string userPin, string localPin, uint localPinId)
        {
            if (userPin == null)
                throw new ArgumentNullException(nameof(userPin));

            if (localPin == null)
                throw new ArgumentNullException(nameof(localPin));

            byte[] userPinArray = ConvertUtils.Utf8StringToBytes(userPin);
            byte[] localPinArray = ConvertUtils.Utf8StringToBytes(localPin);

            CKR rv = slot.LowLevelPkcs11.C_EX_SetLocalPIN(slot.SlotId, userPinArray, localPinArray, localPinId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetLocalPIN", rv);
        }

        public static void SetPIN2(this HLA41.Slot slot, uint pinId)
        {
            CKR rv = slot.LowLevelPkcs11.C_EX_SetLocalPIN(slot.SlotId, null, null, pinId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetLocalPIN", rv);
        }

        public static uint GetDriveSize(this HLA41.Slot slot)
        {
            uint driveSize = 0;
            CKR rv = slot.LowLevelPkcs11.C_EX_GetDriveSize(slot.SlotId, ref driveSize);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetDriveSize", rv);

            return driveSize;
        }

        public static void FormatDrive(this HLA41.Slot slot, CKU userType,
            string pin, IEnumerable<VolumeFormatInfoExtended> initParams)
        {
            if (pin == null)
                throw new ArgumentNullException(nameof(pin));

            if (initParams == null)
                throw new ArgumentNullException(nameof(initParams));

            byte[] pinArray = ConvertUtils.Utf8StringToBytes(pin);

            var formatParams = new List<CK_VOLUME_FORMAT_INFO_EXTENDED>();
            foreach (var initParam in initParams)
            {
                formatParams.Add(initParam.CkVolumeFormatInfoExtended);
            }

            CKR rv = slot.LowLevelPkcs11.C_EX_FormatDrive(slot.SlotId, (uint)userType,
                pinArray, formatParams.ToArray());
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FormatDrive", rv);
        }

        public static ICollection<VolumeInfoExtended> GetVolumesInfo(this HLA41.Slot slot)
        {
            uint volumesInfoCount = 0;
            CKR rv = slot.LowLevelPkcs11.C_EX_GetVolumesInfo(slot.SlotId, null, ref volumesInfoCount);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetVolumesInfo", rv);

            if (volumesInfoCount != 0)
            {
                var volumesInfo = new CK_VOLUME_INFO_EXTENDED[volumesInfoCount];
                rv = slot.LowLevelPkcs11.C_EX_GetVolumesInfo(slot.SlotId, volumesInfo, ref volumesInfoCount);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_GetVolumesInfo", rv);

                return volumesInfo.Select(volumeInfo => new VolumeInfoExtended(volumeInfo)).ToList();
            }

            return null;
        }

        public static void ChangeVolumeAttributes(this HLA41.Slot slot, CKU userType, string pin,
            uint volumeId, FlashAccessMode newAccessMode, bool permanent)
        {
            if (pin == null)
                throw new ArgumentNullException(nameof(pin));

            byte[] pinArray = ConvertUtils.Utf8StringToBytes(pin);

            CKR rv = slot.LowLevelPkcs11.C_EX_ChangeVolumeAttributes(slot.SlotId, (uint)userType,
                pinArray, volumeId, newAccessMode, permanent);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_ChangeVolumeAttributes", rv);
        }

        public static void SetActivationPassword(this HLA41.Slot slot, byte[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            CKR rv = slot.LowLevelPkcs11.C_EX_SetActivationPassword(
                slot.SlotId, password);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetActivationPassword", rv);
        }

        public static void SlotManage(this HLA41.Slot slot, uint mode, byte[] value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            IntPtr valuePtr = Marshal.AllocHGlobal(value.Length);
            Marshal.Copy(value, 0, valuePtr, value.Length);

            try
            {
                CKR rv = slot.LowLevelPkcs11.C_EX_SlotManage(slot.SlotId, mode, valuePtr);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_SlotManage", rv);
            }
            finally
            {
                Marshal.FreeHGlobal(valuePtr);
            }
        }
    }
}
