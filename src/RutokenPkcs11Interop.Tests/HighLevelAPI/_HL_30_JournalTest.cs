using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_30_JournalTest
    {
        [Test()]
        public void _HL_30_01_SignJournalTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3411_12_512);

                    byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] dataDigest = session.Digest(digestMechanism, sourceData);

                    // Генерация ключевой пары ГОСТ Р 34.10-2012
                    IObjectHandle dataPublicKey = null;
                    IObjectHandle dataPrivateKey = null;
                    Helpers.GenerateGost512KeyPair(session, out dataPublicKey, out dataPrivateKey, Settings.Gost512KeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                    var signMechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3410_512);

                    // Подпись данных
                    byte[] dataSignature = session.Sign(signMechanism, dataPrivateKey, dataDigest);

                    // Проверка подписи для данных
                    bool isValid = false;
                    session.Verify(signMechanism, dataPublicKey, dataDigest, dataSignature, out isValid);

                    Assert.IsTrue(isValid);

                    // Получение журнала операций
                    byte[] journal = slot.GetJournal();

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 для подписи журнала
                    IObjectHandle journalPublicKey = null;
                    IObjectHandle journalPrivateKey = null;
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

        [Test()]
        public void _HL_30_02_SignInvisibleJournalTest()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                var slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (var session = (IRutokenSession) slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Инициализация хэш-функции
                    var digestMechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3411_12_512);

                    string sourceData = TestData.Sign_PINPad_SourceData;

                    // Вычисление хэш-кода данных
                    byte[] dataDigest = session.Digest(digestMechanism, ConvertUtils.Utf8StringToBytes(sourceData));

                    // Генерация ключевой пары ГОСТ Р 34.10-2012
                    IObjectHandle dataPublicKey = null;
                    IObjectHandle dataPrivateKey = null;
                    Helpers.GenerateGost512PINPadPair(session, out dataPublicKey, out dataPrivateKey, Settings.Gost512KeyPairId1);

                    // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                    var signMechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3410_512);

                    // Подпись данных
                    byte[] dataSignature = session.SignInvisible(signMechanism, dataPrivateKey, dataDigest);

                    // Проверка подписи для данных
                    bool isValid = false;
                    session.Verify(signMechanism, dataPublicKey, dataDigest, dataSignature, out isValid);

                    Assert.IsTrue(isValid);

                    // Получение журнала операций
                    byte[] journal = slot.GetJournal();

                    // Генерация ключевой пары ГОСТ Р 34.10-2012 для подписи журнала
                    IObjectHandle journalPublicKey = null;
                    IObjectHandle journalPrivateKey = null;
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
