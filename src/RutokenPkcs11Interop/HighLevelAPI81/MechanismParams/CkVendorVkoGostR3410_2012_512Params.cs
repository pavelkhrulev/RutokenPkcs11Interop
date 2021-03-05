using System;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI81.MechanismParams;
using Net.RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

using NativeULong = System.UInt64;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.HighLevelAPI81.MechanismParams
{
    public class CkVendorVkoGostR3410_2012_512Params : ICkVendorVkoGostR3410_2012_512Params
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private readonly CK_VENDOR_VKO_GOSTR3410_2012_512_PARAMS _lowLevelStruct;

        public CkVendorVkoGostR3410_2012_512Params(ulong kdf, byte[] publicData, byte[] ukm)
        {
            _lowLevelStruct.kdf = 0;
            _lowLevelStruct.pPublicData = IntPtr.Zero;
            _lowLevelStruct.ulPublicDataLen = 0;
            _lowLevelStruct.pUKM = IntPtr.Zero;
            _lowLevelStruct.ulUKMLen = 0;

            if (publicData == null)
                throw new ArgumentNullException(nameof(publicData));

            if (publicData.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(publicData), "Array has to be not null length");

            if (ukm == null)
                throw new ArgumentNullException(nameof(ukm));

            if (ukm.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(ukm), "has to be not null length");

            _lowLevelStruct.kdf = (NativeULong)kdf;

            _lowLevelStruct.ulPublicDataLen = (NativeULong)publicData.Length;
            _lowLevelStruct.pPublicData = UnmanagedMemory.Allocate(publicData.Length);
            UnmanagedMemory.Write(_lowLevelStruct.pPublicData, publicData);

            _lowLevelStruct.ulUKMLen = (NativeULong)ukm.Length;
            _lowLevelStruct.pUKM = UnmanagedMemory.Allocate(ukm.Length);
            UnmanagedMemory.Write(_lowLevelStruct.pUKM, ukm);
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
        ~CkVendorVkoGostR3410_2012_512Params()
        {
            Dispose(false);
        }

        #endregion
    }
}
