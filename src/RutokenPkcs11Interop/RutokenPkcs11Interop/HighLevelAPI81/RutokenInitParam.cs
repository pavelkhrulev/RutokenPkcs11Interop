using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.LowLevelAPI81;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11Interop.HighLevelAPI81
{
    public class RutokenInitParam : IRutokenInitParam
    {
        private bool _disposed = false;

        private CK_RUTOKEN_INIT_PARAM _ckRutokenInitParam;

        internal CK_RUTOKEN_INIT_PARAM CkRutokenInitParam
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _ckRutokenInitParam;
            }
            set { _ckRutokenInitParam = value; }
        }

        public RutokenInitParam(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, ulong minAdminPinLen, ulong minUserPinLen,
            ulong maxAdminRetryCount, ulong maxUserRetryCount, ulong smMode)
        {
            _ckRutokenInitParam = new CK_RUTOKEN_INIT_PARAM()
            {
                SizeofThisStructure = Convert.ToUInt64(Marshal.SizeOf(typeof(CK_RUTOKEN_INIT_PARAM)))
            };

            if (!string.IsNullOrEmpty(newAdminPin))
            {
                var newAdminPinArray = ConvertUtils.Utf8StringToBytes(newAdminPin);
                _ckRutokenInitParam.NewAdminPin = UnmanagedMemory.Allocate(newAdminPinArray.Length);
                UnmanagedMemory.Write(_ckRutokenInitParam.NewAdminPin, newAdminPinArray);
                _ckRutokenInitParam.NewAdminPinLen = Convert.ToUInt64(newAdminPinArray.Length);
            }

            if (!string.IsNullOrEmpty(newUserPin))
            {
                var newUserPinArray = ConvertUtils.Utf8StringToBytes(newUserPin);
                _ckRutokenInitParam.NewUserPin = UnmanagedMemory.Allocate(newUserPinArray.Length);
                UnmanagedMemory.Write(_ckRutokenInitParam.NewUserPin, newUserPinArray);
                _ckRutokenInitParam.NewUserPinLen = Convert.ToUInt64(newUserPinArray.Length);
            }

            if (!string.IsNullOrEmpty(tokenLabel))
            {
                var tokenLabelArray = ConvertUtils.Utf8StringToBytes(tokenLabel);
                _ckRutokenInitParam.TokenLabel = UnmanagedMemory.Allocate(tokenLabelArray.Length);
                UnmanagedMemory.Write(_ckRutokenInitParam.TokenLabel, tokenLabelArray);
                _ckRutokenInitParam.LabelLen = Convert.ToUInt64(tokenLabelArray.Length);
            }

            if (changeUserPINPolicy != null)
            {
                foreach (var flag in changeUserPINPolicy)
                {
                    _ckRutokenInitParam.ChangeUserPINPolicy |= Convert.ToUInt64(flag);
                }
            }

            _ckRutokenInitParam.MinAdminPinLen = minAdminPinLen;
            _ckRutokenInitParam.MinUserPinLen = minUserPinLen;
            _ckRutokenInitParam.MaxAdminRetryCount = maxAdminRetryCount;
            _ckRutokenInitParam.MaxUserRetryCount = maxUserRetryCount;
            _ckRutokenInitParam.SmMode = smMode;
        }

        public RutokenInitParam(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, ulong minAdminPinLen, ulong minUserPinLen,
            ulong maxAdminRetryCount, ulong maxUserRetryCount, ulong smMode, bool useRepairMode)
            : this(newAdminPin, newUserPin, tokenLabel, changeUserPINPolicy, minAdminPinLen, minUserPinLen, maxAdminRetryCount, maxUserRetryCount, smMode)
        {
            _ckRutokenInitParam.UseRepairMode = Convert.ToUInt64(useRepairMode);
        }

        #region IDisposable

        /// <summary>
        /// Disposes object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes object
        /// </summary>
        /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!this._disposed)
            {
                if (disposing)
                {
                    // Dispose managed objects
                }

                // Dispose unmanaged objects
                UnmanagedMemory.Free(ref _ckRutokenInitParam.NewAdminPin);
                _ckRutokenInitParam.NewAdminPinLen = 0;

                UnmanagedMemory.Free(ref _ckRutokenInitParam.NewUserPin);
                _ckRutokenInitParam.NewUserPinLen = 0;

                UnmanagedMemory.Free(ref _ckRutokenInitParam.TokenLabel);
                _ckRutokenInitParam.LabelLen = 0;

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~RutokenInitParam()
        {
            Dispose(false);
        }

        #endregion
    }
}