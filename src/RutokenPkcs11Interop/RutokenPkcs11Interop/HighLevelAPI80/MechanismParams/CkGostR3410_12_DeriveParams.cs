using System;
using RutokenPkcs11Interop.LowLevelAPI80.MechanismParams;
using RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

namespace RutokenPkcs11Interop.HighLevelAPI80.MechanismParams
{
    public class CkGostR3410_12_DeriveParams : ICkGostR3410_12_DeriveParams
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private readonly CK_GOSTR3410_12_DERIVE_PARAMS _lowLevelStruct;

        /// <summary>
        /// Initializes a new instance of the CkGostR3410DeriveParams class.
        /// </summary>
        /// <param name="kdf">Additional key diversification algorithm (CKD)</param>
        /// <param name="publicData">Data with public key of a receiver</param>
        /// <param name="ukm">UKM data</param>
        public CkGostR3410_12_DeriveParams(ulong kdf, byte[] publicData, byte[] ukm)
        {
            _lowLevelStruct.Kdf = 0;
            _lowLevelStruct.PublicDataLen = 0;
            _lowLevelStruct.PublicData = new byte[128];
            _lowLevelStruct.UKMLen = 0;
            _lowLevelStruct.UKM = new byte[8];

            if (publicData == null)
                throw new ArgumentNullException(nameof(publicData));

            if (publicData.Length != 128)
                throw new ArgumentOutOfRangeException(nameof(publicData), "Array has to be 128 bytes long");

            if (ukm == null)
                throw new ArgumentNullException(nameof(ukm));

            if (ukm.Length != 8)
                throw new ArgumentOutOfRangeException(nameof(ukm), "Array has to be 8 bytes long");

            _lowLevelStruct.Kdf = kdf;
            _lowLevelStruct.PublicDataLen = Convert.ToUInt64(publicData.Length);
            Array.Copy(publicData, _lowLevelStruct.PublicData, publicData.Length);
            _lowLevelStruct.UKMLen = Convert.ToUInt64(ukm.Length);
            Array.Copy(ukm, _lowLevelStruct.UKM, ukm.Length);
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

            return _lowLevelStruct;
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
                    // Dispose managed objects
                }

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~CkGostR3410_12_DeriveParams()
        {
            Dispose(false);
        }

        #endregion
    }
}
