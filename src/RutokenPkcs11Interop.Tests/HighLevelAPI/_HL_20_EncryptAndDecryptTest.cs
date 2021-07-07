using System;
using System.IO;
using Net.Pkcs11Interop.Common;
using NUnit.Framework;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
{
    [TestFixture()]
    public class _HL_20_EncryptAndDecryptTest
    {
        /// <summary>
        /// C_EncryptInit, C_Encrypt, C_DecryptInit and C_Decrypt test.
        /// </summary>
        [Test()]
        public void _HL_20_01_EncryptAndDecrypt_Gost28147_89_ECB_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Generate symetric key
                    IObjectHandle generatedKey = Helpers.GenerateGost28147_89Key(session);

                    var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_ECB);

                    byte[] sourceData = TestData.Encrypt_Gost28147_89_ECB_SourceData;

                    // Encrypt data
                    byte[] encryptedData = session.Encrypt(mechanism, generatedKey, sourceData);

                    // Decrypt data
                    byte[] decryptedData = session.Decrypt(mechanism, generatedKey, encryptedData);

                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);
                    session.Logout();
                }
            }
        }

        /// <summary>
        /// C_EncryptInit, C_EncryptUpdate, C_EncryptFinish, C_DecryptInit, C_DecryptUpdate and C_DecryptFinish test.
        /// </summary>
        [Test()]
        public void _HL_20_02_EncryptAndDecrypt_Gost28147_89_Stream_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Generate symetric key
                    IObjectHandle generatedKey = Helpers.GenerateGost28147_89Key(session);

                    // Specify encryption mechanism with initialization vector as parameter
                    var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147);

                    byte[] sourceData = TestData.Encrypt_Gost28147_89_SourceData;
                    byte[] encryptedData = null;
                    byte[] decryptedData = null;

                    // Multipart encryption can be used i.e. for encryption of streamed data
                    using (MemoryStream inputStream = new MemoryStream(sourceData), outputStream = new MemoryStream())
                    {
                        // Encrypt data
                        // Note that in real world application we would rather use bigger read buffer i.e. 4096
                        session.Encrypt(mechanism, generatedKey, inputStream, outputStream, 8);

                        // Read whole output stream to the byte array so we can compare results more easily
                        encryptedData = outputStream.ToArray();
                    }

                    // Do something interesting with encrypted data

                    // Multipart decryption can be used i.e. for decryption of streamed data
                    using (MemoryStream inputStream = new MemoryStream(encryptedData), outputStream = new MemoryStream())
                    {
                        // Decrypt data
                        // Note that in real world application we would rather use bigger read buffer i.e. 4096
                        session.Decrypt(mechanism, generatedKey, inputStream, outputStream, 8);

                        // Read whole output stream to the byte array so we can compare results more easily
                        decryptedData = outputStream.ToArray();
                    }

                    // Do something interesting with decrypted data
                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);
                    session.Logout();
                }
            }
        }

        /// <summary>
        /// C_EncryptInit, C_Encrypt, C_DecryptInit and C_Decrypt test.
        /// </summary>
        [Test()]
        public void _HL_20_03_EncryptAndDecrypt_Gost28147_89_CBC_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Find first slot with token present
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Open RW session
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Login as normal user
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Generate symetric key
                    IObjectHandle generatedKey = Helpers.GenerateGost28147_89Key(session);

                    byte[] sourceData = TestData.Encrypt_CBC_Gost28147_89_ECB_SourceData;

                    // Получение синхропосылки
                    var random = new Random();
                    byte[] initVector = new byte[Settings.GOST28147_89_BLOCK_SIZE];
                    random.NextBytes(initVector);

                    // Encrypt data
                    byte[] encryptedData = Helpers.CBC_Gost28147_89_Encrypt(
                        session, sourceData, initVector, generatedKey);

                    // Decrypt data
                    byte[] decryptedData = Helpers.CBC_Gost28147_89_Decrypt(
                        session, encryptedData, initVector, generatedKey);

                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);
                    session.Logout();
                }
            }
        }

        /// <summary>
        /// C_EncryptInit, C_Encrypt, C_DecryptInit and C_Decrypt test.
        /// </summary>
        [Test()]
        public void _HL_20_04_EncryptAndDecrypt_RSA_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                ISlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключей для RSA шифрования
                    IObjectHandle privateKeyHandle = null;
                    IObjectHandle publicKeyHandle = null;
                    Helpers.GenerateRSAKeyPair(session, out publicKeyHandle, out privateKeyHandle, Settings.RsaKeyPairId);

                    // Инициализация механизма шифрования
                    var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS);

                    byte[] sourceData = TestData.Encrypt_RSA_SourceData;

                    // Получение зашифрованных данных
                    byte[] encryptedData = session.Encrypt(mechanism, publicKeyHandle, sourceData);

                    // Получение расшифрованных данных
                    byte[] decryptedData = session.Decrypt(mechanism, privateKeyHandle, encryptedData);

                    // Проверка результата
                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    // Уничтожение созданных RSA ключей
                    session.DestroyObject(privateKeyHandle);
                    session.DestroyObject(publicKeyHandle);

                    // Завершение сессии
                    session.Logout();
                }
            }
        }

        [Test()]
        public void _HL_20_05_EncryptAndDecrypt_Kuznechik_ECB_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                IRutokenSlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключей для шифрования Кузнечик
                    // Generate symetric key
                    IObjectHandle generatedKey = Helpers.GenerateKuznechikKey(session);

                    var mechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_KUZNECHIK_ECB);

                    byte[] sourceData = TestData.Encrypt_Gost28147_89_ECB_SourceData;

                    // Encrypt data
                    byte[] encryptedData = session.Encrypt(mechanism, generatedKey, sourceData);

                    // Decrypt data
                    byte[] decryptedData = session.Decrypt(mechanism, generatedKey, encryptedData);

                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);

                    // Завершение сессии
                    session.Logout();
                }
            }
        }

        [Test()]
        public void _HL_20_06_EncryptAndDecrypt_Magma_ECB_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                IRutokenSlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключей для шифрования Магма
                    // Generate symetric key
                    IObjectHandle generatedKey = Helpers.GenerateMagmaKey(session);

                    var mechanism = Settings.Factories.MechanismFactory.Create((CKM)Extended_CKM.CKM_MAGMA_ECB);

                    byte[] sourceData = TestData.Encrypt_Gost28147_89_ECB_SourceData;

                    // Encrypt data
                    byte[] encryptedData = session.Encrypt(mechanism, generatedKey, sourceData);

                    // Decrypt data
                    byte[] decryptedData = session.Decrypt(mechanism, generatedKey, encryptedData);

                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);

                    // Завершение сессии
                    session.Logout();
                }
            }
        }

        [Test()]
        public void _HL_20_07_EncryptAndDecrypt_Kuznechik_CTR_ACPKM_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                IRutokenSlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключей для шифрования Кузнечик
                    // Generate symetric key
                    IObjectHandle generatedKey = Helpers.GenerateKuznechikKey(session);

                    var random = new Random();
                    byte[] initVector = new byte[Settings.KUZNYECHIK_BLOCK_SIZE / 2];
                    random.NextBytes(initVector);

                    byte[] mechaismParams = new byte[Settings.CTR_ACPKM_PERIOD_SIZE + Settings.KUZNYECHIK_BLOCK_SIZE / 2 ];

                    mechaismParams[0] = 0x01;
                    mechaismParams[1] = 0x00;
                    mechaismParams[2] = 0x00;
                    mechaismParams[3] = 0x00;
                    Array.Copy(initVector, 0, mechaismParams, Settings.CTR_ACPKM_PERIOD_SIZE, initVector.Length);

                    var mechanism = Settings.Factories.MechanismFactory.Create((CKM)Extended_CKM.CKM_KUZNYECHIK_CTR_ACPKM, mechaismParams);

                    byte[] sourceData = TestData.Encrypt_Gost28147_89_ECB_SourceData;

                    // Encrypt data
                    byte[] encryptedData = session.Encrypt(mechanism, generatedKey, sourceData);

                    // Decrypt data
                    byte[] decryptedData = session.Decrypt(mechanism, generatedKey, encryptedData);

                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);

                    // Завершение сессии
                    session.Logout();
                }
            }
        }

        [Test()]
        public void _HL_20_08_EncryptAndDecrypt_Magma_CTR_ACPKM_Test()
        {
            using (var pkcs11 = Settings.Factories.RutokenPkcs11LibraryFactory.LoadRutokenPkcs11Library(Settings.Factories, Settings.Pkcs11LibraryPath, Settings.AppType))
            {
                // Установление соединения с Рутокен в первом доступном слоте
                IRutokenSlot slot = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                using (ISession session = slot.OpenRutokenSession(SessionType.ReadWrite))
                {
                    // Выполнение аутентификации пользователя
                    session.Login(CKU.CKU_USER, Settings.NormalUserPin);

                    // Генерация ключей для шифрования Магма
                    // Generate symetric key
                    IObjectHandle generatedKey = Helpers.GenerateMagmaKey(session);

                    var random = new Random();
                    byte[] initVector = new byte[Settings.MAGMA_BLOCK_SIZE / 2];
                    random.NextBytes(initVector);

                    byte[] mechaismParams = new byte[Settings.CTR_ACPKM_PERIOD_SIZE + Settings.MAGMA_BLOCK_SIZE / 2];

                    mechaismParams[0] = 0x01;
                    mechaismParams[1] = 0x00;
                    mechaismParams[2] = 0x00;
                    mechaismParams[3] = 0x00;
                    Array.Copy(initVector, 0, mechaismParams, Settings.CTR_ACPKM_PERIOD_SIZE, initVector.Length);

                    var mechanism = Settings.Factories.MechanismFactory.Create((CKM)Extended_CKM.CKM_MAGMA_CTR_ACPKM, mechaismParams);

                    byte[] sourceData = TestData.Encrypt_Gost28147_89_ECB_SourceData;

                    // Encrypt data
                    byte[] encryptedData = session.Encrypt(mechanism, generatedKey, sourceData);

                    // Decrypt data
                    byte[] decryptedData = session.Decrypt(mechanism, generatedKey, encryptedData);

                    Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                    session.DestroyObject(generatedKey);

                    // Завершение сессии
                    session.Logout();
                }
            }
        }
    }
}
