using System;
using Net.Pkcs11Interop.Common;

namespace RutokenPkcs11Interop.HighLevelAPI.MechanismParams
{
    public class CkGostR3410_12_256_DeriveParams : IMechanismParams, IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// Platform specific CkGostR3410_12_DeriveParams
        /// </summary>
        private HighLevelAPI41.MechanismParams.CkGostR3410_12_256_DeriveParams _params41;

        /// <summary>
        /// Platform specific CkGostR3410_12_DeriveParams
        /// </summary>
        private HighLevelAPI81.MechanismParams.CkGostR3410_12_256_DeriveParams _params81;

        /// <summary>
        /// Initializes a new instance of the CkGostR3410_12_DeriveParams class.
        /// </summary>
        /// <param name='kdf'>Additional key diversification algorithm (CKD)</param>
        /// <param name='publicData'>Public key (64 bytes long)</param>
        /// <param name='ukm'>UKM (8 bytes)</param>
        public CkGostR3410_12_256_DeriveParams(uint kdf, byte[] publicData, byte[] ukm)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    throw new NotImplementedException();
                else
                    _params41 = new HighLevelAPI41.MechanismParams.CkGostR3410_12_256_DeriveParams(kdf, publicData, ukm);
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    throw new NotImplementedException();
                else
                    _params81 = new HighLevelAPI81.MechanismParams.CkGostR3410_12_256_DeriveParams(kdf, publicData, ukm);
            }
        }

        #region IMechanismParams

        /// <summary>
        /// Returns managed object that can be marshaled to an unmanaged block of memory
        /// </summary>
        /// <returns>A managed object holding the data to be marshaled. This object must be an instance of a formatted class.</returns>
        public object ToMarshalableStructure()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                    throw new NotImplementedException();
                else
                    return _params41.ToMarshalableStructure();
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                    throw new NotImplementedException();
                else
                    return _params81.ToMarshalableStructure();
            }
        }

        #endregion

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
                    if (_params41 != null)
                    {
                        _params41.Dispose();
                        _params41 = null;
                    }

                    if (_params81 != null)
                    {
                        _params81.Dispose();
                        _params81 = null;
                    }
                }

                // Dispose unmanaged objects
                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkGostR3410_12_256_DeriveParams()
        {
            Dispose(false);
        }

        #endregion
    }
}
