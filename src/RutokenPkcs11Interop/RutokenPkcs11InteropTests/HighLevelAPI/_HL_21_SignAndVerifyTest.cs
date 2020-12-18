using Net.Pkcs11Interop.Common;
using NUnit.Framework;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_21_SignAndVerifyTest
    {
        /// <summary>
        /// C_SignInit, C_Sign, C_VerifyInit and C_Verify test.
        /// </summary>
        [Test()]
        public void _HL_21_01_SignAndVerify_Gost3410_01_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = Settings.Factories.MechanismFactory.Create((uint)Extended_CKM.CKM_GOSTR3411);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2001
                    IObjectHandle publicKey = null;
                    IObjectHandle privateKey = null;
                    Helpers.GenerateGostKeyPair(session, out publicKey, out privateKey, Settings.GostKeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2001
                    var signMechanism = Settings.Factories.MechanismFactory.Create((uint)Extended_CKM.CKM_GOSTR3410);

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
        public void _HL_21_02_SignAndVerify_Gost3410_12_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = Settings.Factories.MechanismFactory.Create((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012
                    IObjectHandle publicKey = null;
                    IObjectHandle privateKey = null;
                    Helpers.GenerateGost512KeyPair(session, out publicKey, out privateKey, Settings.Gost512KeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                    var signMechanism = Settings.Factories.MechanismFactory.Create((uint)Extended_CKM.CKM_GOSTR3410_512);

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
        public void _HL_21_03_SignAndVerify_RSA_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_SHA_1);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] digest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары RSA
                    IObjectHandle publicKey = null;
                    IObjectHandle privateKey = null;
                    Helpers.GenerateRSAKeyPair(session, out publicKey, out privateKey, Settings.RsaKeyPairId);

                    // Инициализация операции подписи данных по алгоритму RSA
                    var signMechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);

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
