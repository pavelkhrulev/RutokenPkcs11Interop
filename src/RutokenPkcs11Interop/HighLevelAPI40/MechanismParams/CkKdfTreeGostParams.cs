using System;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI40.MechanismParams;
using Net.RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.HighLevelAPI40.MechanismParams
{
    public class CkKdfTreeGostParams : ICkKdfTreeGostParams
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// Low level mechanism parameters
        /// </summary>
        private readonly CK_KDF_TREE_GOST_PARAMS _lowLevelStruct;

        public CkKdfTreeGostParams(byte[] label, byte[] seed, long r, long l, long offset)
        {
            _lowLevelStruct.ulLabelLength = 0;
            _lowLevelStruct.pLabel = IntPtr.Zero;
            _lowLevelStruct.ulSeedLength = 0;
            _lowLevelStruct.pSeed = IntPtr.Zero;
            _lowLevelStruct.ulR = 0;
            _lowLevelStruct.ulL = 0;
            _lowLevelStruct.ulOffset = 0;

            if (label == null)
                throw new ArgumentNullException(nameof(label));

            if (label.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(label), "Array has to be not null length");

            if (seed == null)
                throw new ArgumentNullException(nameof(seed));

            if (seed.Length == 0)
                throw new ArgumentOutOfRangeException(nameof(seed), "has to be not null length");

            if (r < 1 || r > 4)
                throw new ArgumentOutOfRangeException(nameof(r), "R has to be 1, 2, 3 or 4");

            if (l <= 0)
                throw new ArgumentOutOfRangeException(nameof(l), "L has to be bigger then 0");

            if (l < offset)
                throw new ArgumentOutOfRangeException(nameof(offset), "Offset has to be not bigger then L");

            _lowLevelStruct.ulLabelLength = (NativeULong) label.Length;
            _lowLevelStruct.pLabel = UnmanagedMemory.Allocate(label.Length);
            UnmanagedMemory.Write(_lowLevelStruct.pLabel, label);

            _lowLevelStruct.ulSeedLength = (NativeULong)seed.Length;
            _lowLevelStruct.pSeed = UnmanagedMemory.Allocate(seed.Length);
            UnmanagedMemory.Write(_lowLevelStruct.pSeed, seed);

            _lowLevelStruct.ulR = (NativeULong)(r);
            _lowLevelStruct.ulL = (NativeULong)(l);
            _lowLevelStruct.ulOffset = (NativeULong)(offset);
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
        ~CkKdfTreeGostParams()
        {
            Dispose(false);
        }

        #endregion
    }
}
