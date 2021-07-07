﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;

using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Common;

using Net.RutokenPkcs11Interop.HighLevelAPI;

using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.HighLevelAPI81
{
    public class RutokenSlot : Net.Pkcs11Interop.HighLevelAPI81.Slot, IRutokenSlot
    {
        internal RutokenSlot(Net.Pkcs11Interop.HighLevelAPI.Pkcs11InteropFactories factories
            , LowLevelAPI81.RutokenPkcs11Library pkcs11Library, ulong slotId)
            : base(factories, pkcs11Library, slotId)
        {
        }

        public IRutokenSession OpenRutokenSession(SessionType sessionType)
        {
            return (IRutokenSession)OpenSession(sessionType);
        }

        public ITokenInfoExtended GetTokenInfoExtended()
        {
            var tokenInfo = new LowLevelAPI81.CK_TOKEN_INFO_EXTENDED
            {
                SizeofThisStructure = (NativeULong)(Marshal.SizeOf(typeof(LowLevelAPI81.CK_TOKEN_INFO_EXTENDED)))
            };

            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_GetTokenInfoExtended(_slotId, ref tokenInfo);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetTokenInfoExtended", rv);

            return new TokenInfoExtended(tokenInfo);
        }

        public void InitTokenExtended(string pin, IRutokenInitParam initParam)
        {
            if (pin == null)
                throw new ArgumentNullException(nameof(pin));

            if (initParam == null)
                throw new ArgumentNullException(nameof(initParam));

            LowLevelAPI81.CK_RUTOKEN_INIT_PARAM ckInitParam = ((RutokenInitParam) initParam).CkRutokenInitParam;

            byte[] pinArray = ConvertUtils.Utf8StringToBytes(pin);
            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_InitToken(_slotId, pinArray, ref ckInitParam);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_InitToken", rv);
        }

        public byte[] GetJournal()
        {
            NativeULong journalLength = 0;
            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_GetJournal(_slotId, null, ref journalLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetJournal", rv);

            byte[] journal = new byte[journalLength];

            rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_GetJournal(_slotId, journal, ref journalLength);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetJournal", rv);

            return journal;
        }

        public void SetLocalPIN(string userPin, string localPin, ulong localPinId)
        {
            if (userPin == null)
                throw new ArgumentNullException(nameof(userPin));

            if (localPin == null)
                throw new ArgumentNullException(nameof(localPin));

            byte[] userPinArray = ConvertUtils.Utf8StringToBytes(userPin);
            byte[] localPinArray = ConvertUtils.Utf8StringToBytes(localPin);

            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_SetLocalPIN(_slotId, userPinArray, localPinArray,(NativeULong)(localPinId));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetLocalPIN", rv);
        }

        public void SetPIN2(ulong pinId)
        {
            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_SetLocalPIN(_slotId, null, null,(NativeULong)(pinId));
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetLocalPIN", rv);
        }

        public ulong GetDriveSize()
        {
            NativeULong driveSize = 0;
            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_GetDriveSize(_slotId, ref driveSize);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetDriveSize", rv);

            return driveSize;
        }

        public void FormatDrive(CKU userType,
            string pin, IEnumerable<IVolumeFormatInfoExtended> initParams)
        {
            if (pin == null)
                throw new ArgumentNullException(nameof(pin));

            if (initParams == null)
                throw new ArgumentNullException(nameof(initParams));

            byte[] pinArray = ConvertUtils.Utf8StringToBytes(pin);

            var formatParams = new List<LowLevelAPI81.CK_VOLUME_FORMAT_INFO_EXTENDED>();
            foreach (var initParam in initParams)
            {
                formatParams.Add(((VolumeFormatInfoExtended) initParam).CkVolumeFormatInfoExtended);
            }

            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_FormatDrive(_slotId, (NativeULong)userType,
                pinArray, formatParams.ToArray());
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FormatDrive", rv);
        }

        public ICollection<IVolumeInfoExtended> GetVolumesInfo()
        {
            NativeULong volumesInfoCount = 0;
            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_GetVolumesInfo(_slotId, null, ref volumesInfoCount);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_GetVolumesInfo", rv);

            if (volumesInfoCount != 0)
            {
                var volumesInfo = new LowLevelAPI81.CK_VOLUME_INFO_EXTENDED[volumesInfoCount];
                rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_GetVolumesInfo(_slotId, volumesInfo, ref volumesInfoCount);
                if (rv != CKR.CKR_OK)
                    throw new Pkcs11Exception("C_EX_GetVolumesInfo", rv);

                if (volumesInfo == null)
                    return null;
                return volumesInfo.Select(volumeInfo => (IVolumeInfoExtended) new VolumeInfoExtended(volumeInfo)).ToList();
            }

            return null;
        }

        public void ChangeVolumeAttributes(CKU userType, string pin,
            ulong volumeId, FlashAccessMode newAccessMode, bool permanent)
        {
            if (pin == null)
                throw new ArgumentNullException(nameof(pin));

            byte[] pinArray = ConvertUtils.Utf8StringToBytes(pin);

            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_ChangeVolumeAttributes(_slotId, (NativeULong)userType,
                pinArray,(NativeULong)(volumeId), newAccessMode, permanent);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_ChangeVolumeAttributes", rv);
        }

        public void SetActivationPassword(byte[] password)
        {
            if (password == null)
                throw new ArgumentNullException(nameof(password));

            CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_SetActivationPassword(
                _slotId, password);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_SetActivationPassword", rv);
        }

        public void SlotManage(ulong mode, byte[] value)
        {
            if (value == null)
                throw new ArgumentNullException(nameof(value));

            IntPtr valuePtr = Marshal.AllocHGlobal(value.Length);
            Marshal.Copy(value, 0, valuePtr, value.Length);

            try
            {
                CKR rv = ((LowLevelAPI81.RutokenPkcs11Library)_pkcs11Library).C_EX_SlotManage(_slotId,(NativeULong)(mode), valuePtr);
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
