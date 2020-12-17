using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.HighLevelAPI.Factories;


namespace RutokenPkcs11Interop.HighLevelAPI
{
    public class RutokenPkcs11InteropFactories : Pkcs11InteropFactories
    {
        protected IVolumeFormatInfoExtendedFactory _volumeFormatInfoExtendedFactory = null;

        public IVolumeFormatInfoExtendedFactory VolumeInfoExtendedFactory
        {
            get
            {
                return _volumeFormatInfoExtendedFactory;
            }
        }

        protected IRutokenInitParamFactory _rutokenInitParamFactory = null;

        public IRutokenInitParamFactory RutokenInitParamFactory
        {
            get
            {
                return _rutokenInitParamFactory;
            }
        }

        public RutokenPkcs11InteropFactories()
            : base()
        {
            _volumeFormatInfoExtendedFactory = new VolumeFormatInfoExtendedFactory();
            _rutokenInitParamFactory = new RutokenInitParamFactory();
            _pkcs11LibraryFactory = new RutokenPkcs11LibraryFactory();
            _slotFactory = new RutokenSlotFactory();
            _sessionFactory = new RutokenSessionFactory();
        }
    }
}
