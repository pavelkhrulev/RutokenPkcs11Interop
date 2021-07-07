using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.HighLevelAPI.Factories;


namespace Net.RutokenPkcs11Interop.HighLevelAPI
{
    public class RutokenPkcs11InteropFactories : Pkcs11InteropFactories
    {
        protected IVolumeFormatInfoExtendedFactory _volumeFormatInfoExtendedFactory = null;

        public IVolumeFormatInfoExtendedFactory VolumeFormatInfoExtendedFactory
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

        protected IVolumeInfoFactory _volumeInfoFactory = null;

        public IVolumeInfoFactory VolumeInfoFactory
        {
            get
            {
                return (IVolumeInfoFactory) _volumeInfoFactory;
            }
        }

        protected IVolumeInfoExtendedFactory _volumeInfoExtendedFactory = null;

        public IVolumeInfoExtendedFactory VolumeInfoExtendedFactory
        {
            get
            {
                return (IVolumeInfoExtendedFactory) _volumeInfoExtendedFactory;
            }
        }

        public IRutokenPkcs11LibraryFactory RutokenPkcs11LibraryFactory
        {
            get
            {
                return (IRutokenPkcs11LibraryFactory) _pkcs11LibraryFactory;
            }
        }

        public IRutokenSlotFactory RutokenSlotFactory
        {
            get
            {
                return (IRutokenSlotFactory) _slotFactory;
            }
        }

        public IRutokenSessionFactory RutokenSessionFactory
        {
            get
            {
                return (IRutokenSessionFactory) _sessionFactory;
            }
        }

        public IRutokenMechanismParamsFactory RutokenMechanismParamsFactory
        {
            get
            {
                return (IRutokenMechanismParamsFactory) _mechanismParamsFactory;
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
            _mechanismParamsFactory = new RutokenMechanismParamsFactory();
            _volumeInfoFactory = new VolumeInfoFactory();
            _volumeInfoExtendedFactory = new VolumeInfoExtendedFactory();
        }
    }
}
