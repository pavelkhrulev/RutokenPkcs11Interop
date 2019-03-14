using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI80;
using NUnit.Framework;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11InteropTests.HighLevelAPI80
{
    [TestFixture()]
    public class _HL80_21_SignAndVerifyTest
    {
        /// <summary>
        /// C_SignInit, C_Sign, C_VerifyInit and C_Verify test.
        /// </summary>
        [Test()]
        public void _HL80_21_01_SignAndVerify_Gost3410_01_Test()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    Mechanism digestMechanism = new Mechanism((ulong)Extended_CKM.CKM_GOSTR3411);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateGostKeyPair(session, out publicKey, out privateKey, Settings.GostKeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2001
                    Mechanism signMechanism = new Mechanism((ulong)Extended_CKM.CKM_GOSTR3410);

                    // Подпись данных
                    byte[] signature = session.Sign(signMechanism, privateKey, digest);

                    // Проверка подписи для данных
                    bool isValid = false;
                    session.Verify(signMechanism, publicKey, digest, signature, out isValid);

                    Assert.IsTrue(isValid);

                    session.DestroyObject(privateKey);
                    session.DestroyObject(publicKey);
                    session.Logout();
                }
            }
        }

        /// <summary>
        /// C_SignInit, C_Sign, C_VerifyInit and C_Verify test.
        /// </summary>
        [Test()]
        public void _HL80_21_02_SignAndVerify_Gost3410_12_Test()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    Mechanism digestMechanism = new Mechanism((ulong)Extended_CKM.CKM_GOSTR3411_12_512);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateGost512KeyPair(session, out publicKey, out privateKey, Settings.Gost512KeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                    Mechanism signMechanism = new Mechanism((ulong)Extended_CKM.CKM_GOSTR3410_512);

                    // Подпись данных
                    byte[] signature = session.Sign(signMechanism, privateKey, digest);

                    // Проверка подписи для данных
                    bool isValid = false;
                    session.Verify(signMechanism, publicKey, digest, signature, out isValid);

                    Assert.IsTrue(isValid);

                    session.DestroyObject(privateKey);
                    session.DestroyObject(publicKey);
                    session.Logout();
                }
            }
        }

        /// <summary>
        /// C_SignInit, C_Sign, C_VerifyInit and C_Verify test.
        /// </summary>
        [Test()]
        public void _HL80_21_03_SignAndVerify_RSA_Test()
        {
            if (Platform.UnmanagedLongSize != 8 || Platform.StructPackingSize != 0)
                Assert.Inconclusive("Test cannot be executed on this platform");

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    Mechanism digestMechanism = new Mechanism(CKM.CKM_SHA_1);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары RSA
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateRSAKeyPair(session, out publicKey, out privateKey, Settings.RsaKeyPairId);

                    // Инициализация операции подписи данных по алгоритму RSA
                    Mechanism signMechanism = new Mechanism(CKM.CKM_RSA_PKCS);

                    // Подпись данных
                    byte[] signature = session.Sign(signMechanism, privateKey, digest);

                    // Проверка подписи для данных
                    bool isValid = false;
                    session.Verify(signMechanism, publicKey, digest, signature, out isValid);

                    Assert.IsTrue(isValid);

                    session.DestroyObject(privateKey);
                    session.DestroyObject(publicKey);
                    session.Logout();
                }
            }
        }
    }
}
