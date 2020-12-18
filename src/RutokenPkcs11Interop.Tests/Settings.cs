using System;
using Net.Pkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;
using LLA40 = Net.Pkcs11Interop.LowLevelAPI40;
using LLA41 = Net.Pkcs11Interop.LowLevelAPI41;
using LLA80 = Net.Pkcs11Interop.LowLevelAPI80;
using LLA81 = Net.Pkcs11Interop.LowLevelAPI81;

namespace RutokenPkcs11InteropTests
{
    public static class Settings
    {
        /// <summary>
        /// Factories to be used by Developer and Pkcs11Interop library
        /// </summary>
        public static RutokenPkcs11InteropFactories Factories = new RutokenPkcs11InteropFactories();

        /// <summary>
        /// Type of application that will be using PKCS#11 library.
        /// When set to AppType.MultiThreaded unmanaged PKCS#11 library performs locking to ensure thread safety.
        /// </summary>
        public static AppType AppType = AppType.MultiThreaded;

        /// <summary>
        /// Relative name or absolute path of unmanaged PKCS#11 library provided by smartcard or HSM vendor.
        /// </summary>
        public static string Pkcs11LibraryPath
        {
            get
            {
#if __ANDROID__
                return @"librtpkcs11ecp.so";
#elif __IOS__
                return string.Empty;
#else
                if (Platform.IsWindows)
                {
                    return "rtpkcs11ecp.dll";
                }
                else if (Platform.IsLinux)
                {
                    return "librtpkcs11ecp.so";
                }
                else if (Platform.IsMacOsX)
                {
                    return "librtpkcs11ecp.dylib";
                }
#endif
                throw new InvalidOperationException("Native rutoken library path is not set");
            }
        }

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

        public static string NewUserPin = @"55555555";

        public static string WrongUserPin = @"00000000";

        public static string LocalPin = @"1234567890";

        /* DEMO метка Rutoken ("длинная") */
        public static string TokenLongLabel = @"!!!Sample Rutoken Long-long-long-long-long label!!!";

        /* DEMO метка Rutoken ("обычная") */
        public static string TokenStdLabel = @"!!!Sample Rutoken label!!!";

        /// <summary>
        /// Application name that is used as a label for all objects created by these tests.
        /// </summary>
        public static string ApplicationName = @"RutokenPkcs11Interop";

        /* DEMO-метка открытого ключа RSA */
        public static string RsaPublicKeyLabel = @"Sample RSA Public Key (Aktiv Co.)";

        /* DEMO-метка закрытого ключа RSA */
        public static string RsaPrivateKeyLabel = @"Sample RSA Private Key (Aktiv Co.)";

        /* DEMO ID пары ключей RSA */
        public static string RsaKeyPairId = @"RSA sample keypair ID (Aktiv Co.)";

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
        public static string Gost512KeyPairId1 = @"GOST R 34.10-2012(512) sample keypair 1 ID (Aktiv Co.)";

        /* DEMO ID пары ключей #2 ГОСТ Р 34.10-2012(512) */
        public static string Gost512KeyPairId2 = @"GOST R 34.10-2012(512) sample keypair 2 ID (Aktiv Co.)";

        /* DEMO-метка общего выработанного ключа */
        public static string DerivedKeyLabel = @"Derived GOST 28147-89 key";

        /* DEMO-метка для маскируемого ключа */
        public static string WrappedKeyLabel =  @"GOST 28147-89 key to wrap";

        /* DEMO-метка для демаскированного ключа */
        public static string UnwrappedKeyLabel = @"Unwrapped GOST 28147-89 key";

        /* Длина модуля ключа RSA в битах */
        public static uint RsaModulusBits = 512;

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

        /* Размер блока в байтах */
        public static int GOST28147_89_BLOCK_SIZE = 8;

        /* Размер симметричного ключа ГОСТ 28147-89 в байтах */
        public static int GOST_28147_KEY_SIZE = 32;

        /* Размер открытого ключа ГОСТ Р 34.10-2001 в байтах */
        public static int GOST_3410_KEY_SIZE = 64;

        /* Размер открытого ключа ГОСТ Р 34.10-2012(512) в байтах */
        public static int GOST_3410_12_512_KEY_SIZE = 128;

        /* Максимальное количество попыток ввода PIN-кода для Администратора */
        public static uint MAX_ADMIN_RETRY_COUNT = 10;

        /* Максимальное количество попыток доступа для Пользователя */
        public static uint MAX_USER_RETRY_COUNT = 10;

        public static uint LocalPinId1 = 0x03;

        public static uint LocalPinId2 = 0x1E;

        /// <summary>
        /// Arguments passed to the C_Initialize function in LowLevelAPI40 tests.
        /// </summary>
        public static LLA40.CK_C_INITIALIZE_ARGS InitArgs40 = null;

        /// <summary>
        /// Arguments passed to the C_Initialize function in LowLevelAPI41 tests.
        /// </summary>
        public static LLA41.CK_C_INITIALIZE_ARGS InitArgs41 = null;

        /// <summary>
        /// Arguments passed to the C_Initialize function in LowLevelAPI80 tests.
        /// </summary>
        public static LLA80.CK_C_INITIALIZE_ARGS InitArgs80 = null;

        /// <summary>
        /// Arguments passed to the C_Initialize function in LowLevelAPI81 tests.
        /// </summary>
        public static LLA81.CK_C_INITIALIZE_ARGS InitArgs81 = null;

        /// <summary>
        /// PIN of the SO user a.k.a. PUK.
        /// </summary>
        public static byte[] SecurityOfficerPinArray = null;

        /// <summary>
        /// PIN of the normal user.
        /// </summary>
        public static byte[] NormalUserPinArray = null;

        public static byte[] NewUserPinArray = null;

        public static byte[] WrongUserPinArray = null;

        public static byte[] LocalPinArray = null;

        public static byte[] TokenLongLabelArray = null;

        public static byte[] TokenStdLabelArray = null;


        /// <summary>
        /// Static class constructor
        /// </summary>
        static Settings()
        {
            // Setup arguments passed to the C_Initialize function
            if (UseOsLocking)
            {
                InitArgs40 = new LLA40.CK_C_INITIALIZE_ARGS
                {
                    Flags = CKF.CKF_OS_LOCKING_OK
                };
                InitArgs41 = new LLA41.CK_C_INITIALIZE_ARGS
                {
                    Flags = CKF.CKF_OS_LOCKING_OK
                };
                InitArgs80 = new LLA80.CK_C_INITIALIZE_ARGS
                {
                    Flags = CKF.CKF_OS_LOCKING_OK
                };
                InitArgs81 = new LLA81.CK_C_INITIALIZE_ARGS
                {
                    Flags = CKF.CKF_OS_LOCKING_OK
                };
            }

            // Convert strings to byte arrays
            SecurityOfficerPinArray = ConvertUtils.Utf8StringToBytes(SecurityOfficerPin);
            NormalUserPinArray = ConvertUtils.Utf8StringToBytes(NormalUserPin);
            NewUserPinArray = ConvertUtils.Utf8StringToBytes(NewUserPin);
            WrongUserPinArray = ConvertUtils.Utf8StringToBytes(WrongUserPin);
            LocalPinArray = ConvertUtils.Utf8StringToBytes(LocalPin);
            TokenLongLabelArray = ConvertUtils.Utf8StringToBytes(TokenLongLabel);
            TokenStdLabelArray = ConvertUtils.Utf8StringToBytes(TokenStdLabel);
        }
    }
}
