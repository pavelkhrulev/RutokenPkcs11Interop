using System;
using System.IO;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using NUnit.Framework;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI41;

using NativeULong = System.UInt32;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI41
{
    /// <summary>
    /// C_EncryptInit, C_Encrypt, C_EncryptUpdate, C_EncryptFinish, C_DecryptInit, C_Decrypt, C_DecryptUpdate and C_DecryptFinish tests.
    /// </summary>
    [TestFixture()]
    public class _LL_20_EncryptAndDecryptTest
    {
        /// <summary>
        /// C_EncryptInit, C_Encrypt, C_DecryptInit and C_Decrypt test.
        /// </summary>
        [Test()]
        public void _LL_20_01_EncryptAndDecrypt_Gost28147_89_ECB_Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Генерация ключа для симметричного шифрования
                NativeULong keyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGostSymmetricKey(pkcs11, session, ref keyId);

                CK_MECHANISM mechanism = CkmUtils.CreateMechanism((NativeULong)CKM.CKM_GOST28147_ECB);

                // Инициализация операции шифрования
                rv = pkcs11.C_EncryptInit(session, ref mechanism, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = TestData.Encrypt_Gost28147_89_ECB_SourceData;

                // Получение длины массива с зашифрованными данными
                NativeULong encryptedDataLen = 0;
                rv = pkcs11.C_Encrypt(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(encryptedDataLen > 0);

                // Выделение памяти для массива с зашифрованными данными
                byte[] encryptedData = new byte[encryptedDataLen];

                // Получение зашифрованных данных
                rv = pkcs11.C_Encrypt(session, sourceData, Convert.ToUInt32(sourceData.Length), encryptedData, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация операции расишфрования
                rv = pkcs11.C_DecryptInit(session, ref mechanism, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Получение длины массива с расшифрованными данными
                NativeULong decryptedDataLen = 0;
                rv = pkcs11.C_Decrypt(session, encryptedData, Convert.ToUInt32(encryptedData.Length), null, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(decryptedDataLen > 0);

                // Выделение памяти для массива с расшифрованными данными
                byte[] decryptedData = new byte[decryptedDataLen];

                // Получение расшифрованных данных
                rv = pkcs11.C_Decrypt(session, encryptedData, Convert.ToUInt32(encryptedData.Length), decryptedData, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                rv = pkcs11.C_DestroyObject(session, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_EncryptInit, C_EncryptUpdate, C_EncryptFinish, C_DecryptInit, C_DecryptUpdate and C_DecryptFinish test.
        /// </summary>
        [Test()]
        public void _LL_20_02_EncryptAndDecrypt_Gost28147_89_Stream_Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Login as normal user
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Generate symetric key
                NativeULong keyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGostSymmetricKey(pkcs11, session, ref keyId);

                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_GOST28147);

                byte[] sourceData = TestData.Encrypt_Gost28147_89_SourceData;
                byte[] encryptedData = null;
                byte[] decryptedData = null;

                // Multipart encryption functions C_EncryptUpdate and C_EncryptFinal can be used i.e. for encryption of streamed data
                using (MemoryStream inputStream = new MemoryStream(sourceData), outputStream = new MemoryStream())
                {
                    // Initialize encryption operation
                    rv = pkcs11.C_EncryptInit(session, ref mechanism, keyId);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Prepare buffer for source data part
                    byte[] part = new byte[8];

                    // Prepare buffer for encrypted data part
                    byte[] encryptedPart = new byte[8];
                    NativeULong encryptedPartLen = Convert.ToUInt32(encryptedPart.Length);

                    // Read input stream with source data
                    int bytesRead = 0;
                    while ((bytesRead = inputStream.Read(part, 0, part.Length)) > 0)
                    {
                        // Encrypt each individual source data part
                        encryptedPartLen = Convert.ToUInt32(encryptedPart.Length);
                        rv = pkcs11.C_EncryptUpdate(session, part, Convert.ToUInt32(bytesRead), encryptedPart, ref encryptedPartLen);
                        if (rv != CKR.CKR_OK)
                            Assert.Fail(rv.ToString());

                        // Append encrypted data part to the output stream
                        outputStream.Write(encryptedPart, 0, Convert.ToInt32(encryptedPartLen));
                    }

                    // Get the length of last encrypted data part in first call
                    byte[] lastEncryptedPart = null;
                    NativeULong lastEncryptedPartLen = 0;
                    rv = pkcs11.C_EncryptFinal(session, null, ref lastEncryptedPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Allocate array for the last encrypted data part
                    lastEncryptedPart = new byte[lastEncryptedPartLen];

                    // Get the last encrypted data part in second call
                    rv = pkcs11.C_EncryptFinal(session, lastEncryptedPart, ref lastEncryptedPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Append the last encrypted data part to the output stream
                    outputStream.Write(lastEncryptedPart, 0, Convert.ToInt32(lastEncryptedPartLen));

                    // Read whole output stream to the byte array so we can compare results more easily
                    encryptedData = outputStream.ToArray();
                }

                // Multipart decryption functions C_DecryptUpdate and C_DecryptFinal can be used i.e. for decryption of streamed data
                using (MemoryStream inputStream = new MemoryStream(encryptedData), outputStream = new MemoryStream())
                {
                    // Initialize decryption operation
                    rv = pkcs11.C_DecryptInit(session, ref mechanism, keyId);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Prepare buffer for encrypted data part
                    byte[] encryptedPart = new byte[8];

                    // Prepare buffer for decrypted data part
                    byte[] part = new byte[8];
                    NativeULong partLen = Convert.ToUInt32(part.Length);

                    // Read input stream with encrypted data
                    int bytesRead = 0;
                    while ((bytesRead = inputStream.Read(encryptedPart, 0, encryptedPart.Length)) > 0)
                    {
                        // Decrypt each individual encrypted data part
                        partLen = Convert.ToUInt32(part.Length);
                        rv = pkcs11.C_DecryptUpdate(session, encryptedPart, Convert.ToUInt32(bytesRead), part, ref partLen);
                        if (rv != CKR.CKR_OK)
                            Assert.Fail(rv.ToString());

                        // Append decrypted data part to the output stream
                        outputStream.Write(part, 0, Convert.ToInt32(partLen));
                    }

                    // Get the length of last decrypted data part in first call
                    byte[] lastPart = null;
                    NativeULong lastPartLen = 0;
                    rv = pkcs11.C_DecryptFinal(session, null, ref lastPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Allocate array for the last decrypted data part
                    lastPart = new byte[lastPartLen];

                    // Get the last decrypted data part in second call
                    rv = pkcs11.C_DecryptFinal(session, lastPart, ref lastPartLen);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Append the last decrypted data part to the output stream
                    outputStream.Write(lastPart, 0, Convert.ToInt32(lastPartLen));

                    // Read whole output stream to the byte array so we can compare results more easily
                    decryptedData = outputStream.ToArray();
                }

                Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                // In LowLevelAPI we have to free unmanaged memory taken by mechanism parameter (iv in this case)
                UnmanagedMemory.Free(ref mechanism.Parameter);
                mechanism.ParameterLen = 0;

                rv = pkcs11.C_DestroyObject(session, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        /// <summary>
        /// C_EncryptInit, C_Encrypt, C_DecryptInit and C_Decrypt test.
        /// </summary>
        [Test()]
        public void _LL_20_03_EncryptAndDecrypt_Gost28147_89_CBC_Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Find first slot with token present
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Login as normal user
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Генерация ключа для симметричного шифрования
                NativeULong keyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGostSymmetricKey(pkcs11, session, ref keyId);

                // Получение исходных данных
                byte[] sourceData = TestData.Encrypt_CBC_Gost28147_89_ECB_SourceData;

                // Получение синхропосылки
                var random = new Random();
                byte[] initVector = new byte[Settings.GOST28147_89_BLOCK_SIZE];
                random.NextBytes(initVector);

                // Шифрование данных
                byte[] encryptedData = Helpers.CBC_Gost28147_89_Encrypt(
                    pkcs11, session, sourceData, initVector, keyId);

                // Расшифрование данных
                byte[] decryptedData = Helpers.CBC_Gost28147_89_Decrypt(
                    pkcs11, session, encryptedData, initVector, keyId);

                // Сравнение результатов
                Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                rv = pkcs11.C_DestroyObject(session, keyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }

        [Test()]
        public void _LL_20_04_EncryptAndDecrypt_RSA_Test()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Генерация ключей для RSA шифрования
                NativeULong privateKeyId = CK.CK_INVALID_HANDLE;
                NativeULong publicKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateRSAKeyPair(pkcs11, session, ref publicKeyId, ref privateKeyId, Settings.RsaKeyPairId);

                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_RSA_PKCS);

                // Инициализация операции шифрования
                rv = pkcs11.C_EncryptInit(session, ref mechanism, publicKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = TestData.Encrypt_RSA_SourceData;

                // Получение длины массива с зашифрованными данными
                NativeULong encryptedDataLen = 0;
                rv = pkcs11.C_Encrypt(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(encryptedDataLen > 0);

                // Выделение памяти для массива с зашифрованными данными
                byte[] encryptedData = new byte[encryptedDataLen];

                // Получение зашифрованных данных
                rv = pkcs11.C_Encrypt(session, sourceData, Convert.ToUInt32(sourceData.Length), encryptedData, ref encryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация операции расишфрования
                rv = pkcs11.C_DecryptInit(session, ref mechanism, privateKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Получение длины массива с расшифрованными данными
                NativeULong decryptedDataLen = 0;
                rv = pkcs11.C_Decrypt(session, encryptedData, Convert.ToUInt32(encryptedData.Length), null, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(decryptedDataLen > 0);

                // Выделение памяти для массива с расшифрованными данными
                byte[] decryptedData = new byte[decryptedDataLen];

                // Получение расшифрованных данных
                rv = pkcs11.C_Decrypt(session, encryptedData, Convert.ToUInt32(encryptedData.Length), decryptedData, ref decryptedDataLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(Convert.ToBase64String(sourceData) == Convert.ToBase64String(decryptedData));

                // Уничтожение созданных ключей
                rv = pkcs11.C_DestroyObject(session, privateKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, publicKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Завершение сессии
                rv = pkcs11.C_Logout(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_CloseSession(session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_Finalize(IntPtr.Zero);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
            }
        }
    }
}
