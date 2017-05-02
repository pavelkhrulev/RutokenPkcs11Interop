using Net.Pkcs11Interop.Common;
using LLA41 = Net.Pkcs11Interop.LowLevelAPI41;

namespace RutokenPkcs11InteropTests
{
    public static class Settings
    {
        /// <summary>
        /// Relative name or absolute path of unmanaged PKCS#11 library provided by smartcard or HSM vendor.
        /// </summary>
        public static string Pkcs11LibraryPath = @"rtpkcs11ecp.dll";

        /// <summary>
        /// Flag indicating whether PKCS#11 library should use its internal native threading model for locking.
        /// This should be set to true in all multithreaded applications.
        /// </summary>
        public static bool UseOsLocking = true;

        /// <summary>
        /// Serial number of token (smartcard) that should be used by these tests.
        /// First slot with token present is used when both TokenSerial and TokenLabel properties are null.
        /// </summary>
        public static string TokenSerial = null;

        /// <summary>
        /// Label of the token (smartcard) that should be used by these tests.
        /// First slot with token present is used when both TokenSerial and TokenLabel properties are null.
        /// </summary>
        public static string TokenLabel = null;

        /// <summary>
        /// PIN of the SO user a.k.a. PUK.
        /// </summary>
        public static string SecurityOfficerPin = @"87654321";

        /// <summary>
        /// PIN of the normal user.
        /// </summary>
        public static string NormalUserPin = @"12345678";

        /// <summary>
        /// Application name that is used as a label for all objects created by these tests.
        /// </summary>
        public static string ApplicationName = @"RutokenPkcs11Interop";

        /* DEMO-метка симметричного ключа ГОСТ 28147-89 */
        public static string GostSecretKeyLabel = @"Sample GOST 28147 - 89 Secret Key(Aktiv Co.)";

        /* DEMO ID симметричного ключа ГОСТ 28147-89 */
        public static string GostSecretKeyId = @"GOST 28147-89 Secret Key ID (Aktiv Co.)";

        /* DEMO-метка  открытого ключа #1 ГОСТ Р 34.10-2001 */
        public static string GostPublicKeyLabel = @"Sample GOST R 34.10-2001 Public Key 1 (Aktiv Co.)";

        /* DEMO-метка  закрытого ключа #1 ГОСТ Р 34.10-2001 */
        public static string GostPrivateKeyLabel = @"Sample GOST R 34.10-2001 Private Key 1 (Aktiv Co.)";

        /* DEMO ID пары ключей #1 ГОСТ Р 34.10-2001 */
        public static string GostKeyPairId1 = "GOST R 34.10-2001 sample keypair 1 ID (Aktiv Co.)";

        /* DEMO ID пары ключей #2 ГОСТ Р 34.10-2001 */
        public static string GostKeyPairId2 = "GOST R 34.10-2001 sample keypair 2 ID (Aktiv Co.)";

        /* DEMO-метка  открытого ключа #1 ГОСТ Р 34.10-2012(512) */
        public static string Gost512PublicKeyLabel = @"Sample GOST R 34.10-2012(512) Public Key 1 (Aktiv Co.)";

        /* DEMO-метка  закрытого ключа #1 ГОСТ Р 34.10-2012(512) */
        public static string Gost512PrivateKeyLabel = @"Sample GOST R 34.10-2012(512) Private Key 1 (Aktiv Co.)";

        /* DEMO ID пары ключей #1 ГОСТ Р 34.10-2012(512) */
        public static string Gost512KeyPairId = @"GOST R 34.10-2012(512) sample keypair 1 ID (Aktiv Co.)";

        /* DEMO-метка общего выработанного ключа */
        public static string DerivedKeyLabel = @"Derived GOST 28147-89 key";

        /* DEMO-метка для маскируемого ключа */
        public static string WrappedKeyLabel =  @"GOST 28147-89 key to wrap";

        /* DEMO-метка для демаскированного ключа */
        public static string UnwrappedKeyLabel = @"Unwrapped GOST 28147-89 key";

        /* Набор параметров КриптоПро A алгоритма ГОСТ 28147-89 */
        public static byte[] Gost28147Parameters = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1f, 0x01 };

        /* Набор параметров КриптоПро A алгоритма ГОСТ Р 34.10-2001 */
        public static byte[] GostR3410Parameters = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01 };

        /* Набор параметров КриптоПро A алгоритма ГОСТ Р 34.10-2012(512) */
        public static byte[] GostR3410_512_Parameters = { 0x06, 0x09, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x02, 0x01, 0x02, 0x01 };

        /* Набор параметров КриптоПро алгоритма ГОСТ Р 34.11-1994 */
        public static byte[] GostR3411Parameters = { 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01 };

        /* Набор параметров КриптоПро алгоритма ГОСТ Р 34.11-2012(512) */
        public static byte[] GostR3411_512_Parameters = { 0x06, 0x08, 0x2a, 0x85, 0x03, 0x07, 0x01, 0x01, 0x02, 0x03 };

        /* Размер синхропосылки в байтах */
        public static int UKM_LENGTH = 8;

        /* Размер симметричного ключа ГОСТ 28147-89 в байтах */
        public static int GOST_28147_KEY_SIZE = 32;

        /// <summary>
        /// Arguments passed to the C_Initialize function in LowLevelAPI41 tests.
        /// </summary>
        public static LLA41.CK_C_INITIALIZE_ARGS InitArgs41 = null;

        /// <summary>
        /// PIN of the SO user a.k.a. PUK.
        /// </summary>
        public static byte[] SecurityOfficerPinArray = null;

        /// <summary>
        /// PIN of the normal user.
        /// </summary>
        public static byte[] NormalUserPinArray = null;

        /// <summary>
        /// Static class constructor
        /// </summary>
        static Settings()
        {
            // Uncomment following three lines to enable logging of PKCS#11 calls with PKCS11-LOGGER library
            // System.Environment.SetEnvironmentVariable("PKCS11_LOGGER_LIBRARY_PATH", Pkcs11LibraryPath);
            // System.Environment.SetEnvironmentVariable("PKCS11_LOGGER_LOG_FILE_PATH", @"c:\pkcs11-logger.txt");
            // Pkcs11LibraryPath = @"c:\pkcs11-logger-x86.dll";

            // Setup arguments passed to the C_Initialize function
            if (UseOsLocking)
            {
                InitArgs41 = new LLA41.CK_C_INITIALIZE_ARGS();
                InitArgs41.Flags = CKF.CKF_OS_LOCKING_OK;
            }

            // Convert strings to byte arrays
            SecurityOfficerPinArray = ConvertUtils.Utf8StringToBytes(SecurityOfficerPin);
            NormalUserPinArray = ConvertUtils.Utf8StringToBytes(NormalUserPin);
        }
    }
}
