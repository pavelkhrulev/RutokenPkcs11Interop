using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class RutokenInitParam : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        private HighLevelAPI40.RutokenInitParam _rutokenInitParam40 = null;

        private HighLevelAPI41.RutokenInitParam _rutokenInitParam41 = null;

        private HighLevelAPI80.RutokenInitParam _rutokenInitParam80 = null;

        private HighLevelAPI81.RutokenInitParam _rutokenInitParam81 = null;

        internal HighLevelAPI40.RutokenInitParam RutokenInitParam40
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _rutokenInitParam40;
            }
        }

        internal HighLevelAPI41.RutokenInitParam RutokenInitParam41
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _rutokenInitParam41;
            }
        }

        internal HighLevelAPI80.RutokenInitParam RutokenInitParam80
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _rutokenInitParam80;
            }
        }

        internal HighLevelAPI81.RutokenInitParam RutokenInitParam81
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _rutokenInitParam81;
            }
        }

        public RutokenInitParam(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _rutokenInitParam40 = new HighLevelAPI40.RutokenInitParam(
                        newAdminPin, newUserPin, tokenLabel,
                        changeUserPINPolicy,
                        minAdminPinLen, minUserPinLen,
                        maxAdminRetryCount, maxUserRetryCount,
                        smMode);
                else
                    _rutokenInitParam41 = new HighLevelAPI41.RutokenInitParam(
                        newAdminPin, newUserPin, tokenLabel,
                        changeUserPINPolicy,
                        minAdminPinLen, minUserPinLen,
                        maxAdminRetryCount, maxUserRetryCount,
                        smMode);
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _rutokenInitParam80 = new HighLevelAPI80.RutokenInitParam(
                        newAdminPin, newUserPin, tokenLabel,
                        changeUserPINPolicy,
                        minAdminPinLen, minUserPinLen,
                        maxAdminRetryCount, maxUserRetryCount,
                        smMode);
                else
                    _rutokenInitParam81 = new HighLevelAPI81.RutokenInitParam(
                       newAdminPin, newUserPin, tokenLabel,
                       changeUserPINPolicy,
                       minAdminPinLen, minUserPinLen,
                       maxAdminRetryCount, maxUserRetryCount,
                       smMode);
            }
        }

        public RutokenInitParam(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode, bool useRepairMode)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    _rutokenInitParam40 = new HighLevelAPI40.RutokenInitParam(
                        newAdminPin, newUserPin, tokenLabel,
                        changeUserPINPolicy,
                        minAdminPinLen, minUserPinLen,
                        maxAdminRetryCount, maxUserRetryCount,
                        smMode, useRepairMode);
                else
                    _rutokenInitParam41 = new HighLevelAPI41.RutokenInitParam(
                        newAdminPin, newUserPin, tokenLabel,
                        changeUserPINPolicy,
                        minAdminPinLen, minUserPinLen,
                        maxAdminRetryCount, maxUserRetryCount,
                        smMode, useRepairMode);
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    _rutokenInitParam80 = new HighLevelAPI80.RutokenInitParam(
                        newAdminPin, newUserPin, tokenLabel,
                        changeUserPINPolicy,
                        minAdminPinLen, minUserPinLen,
                        maxAdminRetryCount, maxUserRetryCount,
                        smMode, useRepairMode);
                else
                    _rutokenInitParam81 = new HighLevelAPI81.RutokenInitParam(
                        newAdminPin, newUserPin, tokenLabel,
                        changeUserPINPolicy,
                        minAdminPinLen, minUserPinLen,
                        maxAdminRetryCount, maxUserRetryCount,
                        smMode, useRepairMode);
            }
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
                    if (_rutokenInitParam40 != null)
                    {
                        _rutokenInitParam40.Dispose();
                        _rutokenInitParam40 = null;
                    }

                    if (_rutokenInitParam41 != null)
                    {
                        _rutokenInitParam41.Dispose();
                        _rutokenInitParam41 = null;
                    }

                    if (_rutokenInitParam80 != null)
                    {
                        _rutokenInitParam80.Dispose();
                        _rutokenInitParam80 = null;
                    }

                    if (_rutokenInitParam81 != null)
                    {
                        _rutokenInitParam81.Dispose();
                        _rutokenInitParam81 = null;
                    }
                }

                // Dispose unmanaged objects
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
