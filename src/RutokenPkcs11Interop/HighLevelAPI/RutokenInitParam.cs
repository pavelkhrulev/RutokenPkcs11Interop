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

        private HighLevelAPI41.RutokenInitParam _rutokenInitParam41 = null;

        internal HighLevelAPI41.RutokenInitParam RutokenInitParam41
        {
            get
            {
                if (this._disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _rutokenInitParam41;
            }
        }

        public RutokenInitParam(string newAdminPin, string newUserPin, string tokenLabel,
            IList<RutokenFlag> changeUserPINPolicy, uint minAdminPinLen, uint minUserPinLen,
            uint maxAdminRetryCount, uint maxUserRetryCount, uint smMode)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    throw new NotImplementedException();
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
                    throw new NotImplementedException();
                else
                    throw new NotImplementedException();
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
                    if (_rutokenInitParam41 != null)
                    {
                        _rutokenInitParam41.Dispose();
                        _rutokenInitParam41 = null;
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
