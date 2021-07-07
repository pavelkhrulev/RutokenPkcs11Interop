﻿using System;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI80;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.LowLevelAPI80;

using NativeULong = System.UInt64;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI80
{
    [TestFixture()]
    public class _LL_30_JournalTest
    {
        /// <summary>
        /// Тест для проверки работы журнала.
        /// 1. Проводим операцию подписи данных, чтобы оставить запись в журнале.
        /// 2. Получаем журнал.
        /// 3. Подписываем журнал.
        /// </summary>
        [Test()]
        public void _LL_30_01_SignJournalTest()
        {
            if (Platform.NativeULongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (RutokenPkcs11Library pkcs11 = new RutokenPkcs11Library(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs80);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                NativeULong slotId = Helpers.GetUsableSlot(pkcs11);

                // Открытие RW сессии
                NativeULong session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt64(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK && rv != CKR.CKR_USER_ALREADY_LOGGED_IN)
                    Assert.Fail(rv.ToString());

                // Инициализация хэш-функции
                CK_MECHANISM digestMechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3411_12_512);
                rv = pkcs11.C_DigestInit(session, ref digestMechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData = TestData.Digest_Gost3411_SourceData;

                // Определение размера хэш-кода
                NativeULong dataDigestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), null, ref dataDigestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(dataDigestLen > 0);

                // Вычисление хэш-кода данных
                byte[] dataDigest = new byte[dataDigestLen];
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt64(sourceData.Length), dataDigest, ref dataDigestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2012
                NativeULong dataPublicKeyId = CK.CK_INVALID_HANDLE;
                NativeULong dataPrivateKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGost512KeyPair(pkcs11, session, ref dataPublicKeyId, ref dataPrivateKeyId, Settings.Gost512KeyPairId1);

                // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012
                CK_MECHANISM signMechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3410_512);
                rv = pkcs11.C_SignInit(session, ref signMechanism, dataPrivateKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Определение размера подписи данных
                NativeULong signatureLen = 0;
                rv = pkcs11.C_Sign(session, dataDigest, Convert.ToUInt64(dataDigest.Length), null, ref signatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(signatureLen > 0);

                byte[] signature = new byte[signatureLen];

                // Подпись данных
                rv = pkcs11.C_Sign(session, dataDigest, Convert.ToUInt64(dataDigest.Length), signature, ref signatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация проверки подписи по алгоритму ГОСТ Р 34.10-2012
                rv = pkcs11.C_VerifyInit(session, ref signMechanism, dataPublicKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверить подпись для данных
                rv = pkcs11.C_Verify(session, dataDigest, Convert.ToUInt64(dataDigest.Length), signature, Convert.ToUInt64(signature.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Получение длины журнала операций
                NativeULong journalLen = 0;
                rv = pkcs11.C_EX_GetJournal(slotId, null, ref journalLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(journalLen > 0);

                // Получение журнала операций
                byte[] journal = new byte[journalLen];
                rv = pkcs11.C_EX_GetJournal(slotId, journal, ref journalLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2012 для подписи журнала
                NativeULong journalPublicKeyId = CK.CK_INVALID_HANDLE;
                NativeULong journalPrivateKeyId = CK.CK_INVALID_HANDLE;
                Helpers.GenerateGost512JournalKeyPair(
                    pkcs11, session, ref journalPublicKeyId, ref journalPrivateKeyId);

                // Инициализация хэш-функции
                rv = pkcs11.C_DigestInit(session, ref digestMechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Определение размера хэш-кода для журнала
                NativeULong journalDigestLen = 0;
                rv = pkcs11.C_Digest(session, journal, Convert.ToUInt64(journal.Length), null, ref journalDigestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(journalDigestLen > 0);

                // Вычисление хэш-кода журнала
                byte[] journalDigest = new byte[journalDigestLen];
                rv = pkcs11.C_Digest(session, journal, Convert.ToUInt64(journal.Length), journalDigest, ref journalDigestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012
                rv = pkcs11.C_SignInit(session, ref signMechanism, journalPrivateKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Определение размера подписи журнала
                NativeULong journalSignatureLen = 0;
                rv = pkcs11.C_Sign(session, journalDigest, Convert.ToUInt64(journalDigest.Length), null, ref journalSignatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(journalSignatureLen > 0);

                byte[] journalSignature = new byte[journalSignatureLen];

                // Подпись журнала
                rv = pkcs11.C_Sign(session, journalDigest, Convert.ToUInt64(journalDigest.Length), journalSignature, ref journalSignatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация проверки подписи по алгоритму ГОСТ Р 34.10-2012
                rv = pkcs11.C_VerifyInit(session, ref signMechanism, journalPublicKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверить подпись журнала
                rv = pkcs11.C_Verify(session, journalDigest, Convert.ToUInt64(journalDigest.Length), journalSignature, Convert.ToUInt64(journalSignature.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Уничтожение созданных ключей
                rv = pkcs11.C_DestroyObject(session, dataPrivateKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());
                rv = pkcs11.C_DestroyObject(session, dataPublicKeyId);
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
    }
}
