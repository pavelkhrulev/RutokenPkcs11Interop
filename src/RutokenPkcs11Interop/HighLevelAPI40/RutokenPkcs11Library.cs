using System;
using System.Collections.Generic;
using System.Linq;

using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI40;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.Logging;

using Net.RutokenPkcs11Interop.HighLevelAPI;
using LLA = Net.RutokenPkcs11Interop.LowLevelAPI40;

namespace Net.RutokenPkcs11Interop.HighLevelAPI40
{
    public class RutokenPkcs11Library: Pkcs11Library, IRutokenPkcs11Library
    {
        private Pkcs11InteropLogger _logger = Pkcs11InteropLoggerFactory.GetLogger(typeof(RutokenPkcs11Library));

        public RutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType)
            : base(factories, libraryPath)
        {
            _logger.Debug("RutokenPkcs11Library({0})::ctor1", _libraryPath);

            try
            {
                _logger.Info("Loading PKCS#11 library {0}", _libraryPath);
                _pkcs11Library = new LLA.RutokenPkcs11Library(libraryPath);
                Initialize(appType);
            }
            catch
            {
                if (_pkcs11Library != null)
                {
                    _logger.Info("Unloading PKCS#11 library {0}", _libraryPath);
                    _pkcs11Library.Dispose();
                    _pkcs11Library = null;
                }
                throw;
            }
        }

        public RutokenPkcs11Library(Pkcs11InteropFactories factories, string libraryPath, AppType appType, InitType initType)
            : base(factories, libraryPath)
        {
            _logger.Debug("RutokenPkcs11Library({0})::ctor2", _libraryPath);

            try
            {
                _logger.Info("Loading PKCS#11 library {0}", _libraryPath);
                _pkcs11Library = new LLA.RutokenPkcs11Library(libraryPath, (initType == InitType.WithFunctionList));
                Initialize(appType);
            }
            catch
            {
                if (_pkcs11Library != null)
                {
                    _logger.Info("Unloading PKCS#11 library {0}", _libraryPath);
                    _pkcs11Library.Dispose();
                    _pkcs11Library = null;
                }
                throw;
            }
        }

        public List<IRutokenSlot> GetRutokenSlotList(SlotsType slotsType)
        {
            return GetSlotList(slotsType).Select(slot => (IRutokenSlot) slot).ToList();
        }

        public void FreeBuffer(IntPtr buffer)
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            _logger.Debug("RutokenPkcs11Library({0})::GetUnmanagedStructSizeList", _libraryPath);

            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));

            CKR rv = ((LLA.RutokenPkcs11Library)_pkcs11Library).C_EX_FreeBuffer(buffer);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_EX_FreeBuffer", rv);
        }

        protected override void Dispose(bool disposing)
        {
            _logger.Debug("RutokenPkcs11Library({0})::Dispose", _libraryPath);

            base.Dispose(disposing);
        }
    }
}
