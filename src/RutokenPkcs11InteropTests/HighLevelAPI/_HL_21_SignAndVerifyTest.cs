using Net.Pkcs11Interop.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestClass]
    public class _HL_21_SignAndVerifyTest
    {
        /// <summary>
        /// C_SignInit, C_Sign, C_VerifyInit and C_Verify test.
        /// </summary>
        [TestMethod]
        public void _HL_21_01_SignAndVerify_Gost3410_01_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateGostKeyPair(session, out publicKey, out privateKey, Settings.GostKeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2001
                    var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410);

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
        [TestMethod]
        public void _HL_21_02_SignAndVerify_Gost3410_12_Test()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateGost512KeyPair(session, out publicKey, out privateKey, Settings.Gost512KeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                    var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512);

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
        [TestMethod]
        public void _HL_21_03_SignAndVerify_RSA_Test()
        {
            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, Settings.UseOsLocking))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(false))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = new Mechanism(CKM.CKM_SHA_1);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары RSA
                    ObjectHandle publicKey = null;
                    ObjectHandle privateKey = null;
                    Helpers.GenerateRSAKeyPair(session, out publicKey, out privateKey, Settings.RsaKeyPairId);

                    // Инициализация операции подписи данных по алгоритму RSA
                    var signMechanism = new Mechanism(CKM.CKM_RSA_PKCS);

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
