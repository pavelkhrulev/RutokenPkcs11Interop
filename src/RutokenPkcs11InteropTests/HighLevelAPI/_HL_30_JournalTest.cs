using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestClass]
    public class _HL_30_JournalTest
    {
        [TestMethod]
        public void _HL_30_01_SignJournalTest()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] dataDigest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012
                    ObjectHandle dataPublicKey = null;
                    ObjectHandle dataPrivateKey = null;
                    Helpers.GenerateGost512KeyPair(session, out dataPublicKey, out dataPrivateKey, Settings.Gost512KeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                    var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512);

                    // Подпись данных
                    byte[] dataSignature = session.Sign(signMechanism, dataPrivateKey, dataDigest);

                    // Проверка подписи для данных
                    bool isValid = false;
                    session.Verify(signMechanism, dataPublicKey, dataDigest, dataSignature, out isValid);

                    Assert.IsTrue(isValid);

                    // Получение журнала операций
                    byte[] journal = slot.GetJournal();

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 для подписи журнала
                    ObjectHandle journalPublicKey = null;
                    ObjectHandle journalPrivateKey = null;
                    Helpers.GenerateGost512JournalKeyPair(session, out journalPublicKey, out journalPrivateKey);

                    // Вычисление хэш-кода журнала
                    byte[] journalDigest = session.Digest(digestMechanism, journal);

                    // Подпись журнала
                    byte[] journalSignature = session.Sign(signMechanism, journalPrivateKey, journalDigest);

                    // Проверка подписи журнала
                    isValid = false;
                    session.Verify(signMechanism, journalPublicKey, journalDigest, journalSignature, out isValid);

                    Assert.IsTrue(isValid);

                    // Уничтожение созданных ключей
                    session.DestroyObject(dataPrivateKey);
                    session.DestroyObject(dataPublicKey);
                    session.DestroyObject(journalPrivateKey);
                    session.DestroyObject(journalPublicKey);

                    session.Logout();
                }
            }
        }

        [TestMethod]
        public void _HL_30_02_SignInvisibleJournalTest()
        {
            using (var pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath, AppType.MultiThreaded))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                Slot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (Session session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);

                    string sourceData = TestData.Sign_PINPad_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] dataDigest = session.Digest(digestMechanism, ConvertUtils.Utf8StringToBytes(sourceData));

                    // Генерация ключевой пары ГОСТ Р 34.10-2012
                    ObjectHandle dataPublicKey = null;
                    ObjectHandle dataPrivateKey = null;
                    Helpers.GenerateGost512PINPadPair(session, out dataPublicKey, out dataPrivateKey, Settings.Gost512KeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                    var signMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512);

                    // Подпись данных
                    byte[] dataSignature = session.SignInvisible(signMechanism, dataPrivateKey, dataDigest);

                    // Проверка подписи для данных
                    bool isValid = false;
                    session.Verify(signMechanism, dataPublicKey, dataDigest, dataSignature, out isValid);

                    Assert.IsTrue(isValid);

                    // Получение журнала операций
                    byte[] journal = slot.GetJournal();

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 для подписи журнала
                    ObjectHandle journalPublicKey = null;
                    ObjectHandle journalPrivateKey = null;
                    Helpers.GenerateGost512JournalKeyPair(session, out journalPublicKey, out journalPrivateKey);

                    // Вычисление хэш-кода журнала
                    byte[] journalDigest = session.Digest(digestMechanism, journal);

                    // Подпись журнала
                    byte[] journalSignature = session.SignInvisible(signMechanism, journalPrivateKey, journalDigest);

                    // Проверка подписи журнала
                    isValid = false;
                    session.Verify(signMechanism, journalPublicKey, journalDigest, journalSignature, out isValid);

                    Assert.IsTrue(isValid);

                    // Уничтожение созданных ключей
                    session.DestroyObject(dataPrivateKey);
                    session.DestroyObject(dataPublicKey);

                    //session.DestroyObject(journalPrivateKey);
                    //session.DestroyObject(journalPublicKey);

                    session.Logout();
                }
            }
        }
    }
}
