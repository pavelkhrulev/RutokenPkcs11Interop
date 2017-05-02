﻿using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using NUnit.Framework;
using RutokenPkcs11Interop;

namespace RutokenPkcs11InteropTests.LowLevelAPI41
{
    /// <summary>
    /// C_SignInit, C_Sign, C_SignUpdate, C_SignFinal, C_VerifyInit, C_Verify, C_VerifyUpdate and C_VerifyFinal tests.
    /// </summary>
    [TestFixture()]
    class _21_SignAndVerifyTest
    {
        /// <summary>
        /// C_SignInit, C_Sign, C_VerifyInit and C_Verify test.
        /// </summary>
        [Test()]
        public void _21_01_SignAndVerify_Gost3410_01_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация хэш-функции
                CK_MECHANISM digestMechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3411);
                rv = pkcs11.C_DigestInit(session, ref digestMechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData =
                {
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                };

                // Определение размера хэш-кода
                uint digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Вычисление хэш-кода данных
                byte[] digest = new byte[digestLen];
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2001
                uint pubKeyId = CK.CK_INVALID_HANDLE;
                uint privKeyId = CK.CK_INVALID_HANDLE;
                rv = Helpers.GenerateGostKeyPair(pkcs11, session, ref pubKeyId, ref privKeyId, Settings.GostKeyPairId1);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация операции подписи данны хпо алгоритму ГОСТ Р 34.10-2001
                CK_MECHANISM signMechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3410);
                rv = pkcs11.C_SignInit(session, ref signMechanism, privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Определение размера подписи данных
                uint signatureLen = 0;
                rv = pkcs11.C_Sign(session, digest, Convert.ToUInt32(digest.Length), null, ref signatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(signatureLen > 0);

                byte[] signature = new byte[signatureLen];

                // Подпись данных
                rv = pkcs11.C_Sign(session, digest, Convert.ToUInt32(digest.Length), signature, ref signatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация проверки подписи по алгоритму ГОСТ Р 34.10-2001
                rv = pkcs11.C_VerifyInit(session, ref signMechanism, pubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверить подпись для данных
                rv = pkcs11.C_Verify(session, digest, Convert.ToUInt32(digest.Length), signature, Convert.ToUInt32(signature.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, pubKeyId);
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
        /// C_SignInit, C_Sign, C_VerifyInit and C_Verify test.
        /// </summary>
        [Test()]
        public void _21_02_SignAndVerify_Gost3410_12_Test()
        {
            if (Platform.UnmanagedLongSize != 4 || Platform.StructPackingSize != 1)
                Assert.Inconclusive("Test cannot be executed on this platform");

            CKR rv = CKR.CKR_OK;

            using (Pkcs11 pkcs11 = new Pkcs11(Settings.Pkcs11LibraryPath))
            {
                // Инициализация библиотеки
                rv = pkcs11.C_Initialize(Settings.InitArgs41);
                if ((rv != CKR.CKR_OK) && (rv != CKR.CKR_CRYPTOKI_ALREADY_INITIALIZED))
                    Assert.Fail(rv.ToString());

                // Установление соединения с Рутокен в первом доступном слоте
                uint slotId = Helpers.GetUsableSlot(pkcs11);

                uint session = CK.CK_INVALID_HANDLE;
                rv = pkcs11.C_OpenSession(slotId, (CKF.CKF_SERIAL_SESSION | CKF.CKF_RW_SESSION), IntPtr.Zero, IntPtr.Zero, ref session);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Выполнение аутентификации пользователя
                rv = pkcs11.C_Login(session, CKU.CKU_USER, Settings.NormalUserPinArray, Convert.ToUInt32(Settings.NormalUserPinArray.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация хэш-функции
                CK_MECHANISM digestMechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3411_12_512);
                rv = pkcs11.C_DigestInit(session, ref digestMechanism);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                byte[] sourceData =
                {
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
                };

                // Определение размера хэш-кода
                uint digestLen = 0;
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), null, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(digestLen > 0);

                // Вычисление хэш-кода данных
                byte[] digest = new byte[digestLen];
                rv = pkcs11.C_Digest(session, sourceData, Convert.ToUInt32(sourceData.Length), digest, ref digestLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Генерация ключевой пары ГОСТ Р 34.10-2012
                uint pubKeyId = CK.CK_INVALID_HANDLE;
                uint privKeyId = CK.CK_INVALID_HANDLE;
                rv = Helpers.GenerateGost512KeyPair(pkcs11, session, ref pubKeyId, ref privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация операции подписи данных по алгоритму ГОСТ Р 34.10-2012(512)
                CK_MECHANISM signMechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3410_512);
                rv = pkcs11.C_SignInit(session, ref signMechanism, privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Определение размера подписи данных
                uint signatureLen = 0;
                rv = pkcs11.C_Sign(session, digest, Convert.ToUInt32(digest.Length), null, ref signatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                Assert.IsTrue(signatureLen > 0);

                byte[] signature = new byte[signatureLen];

                // Подпись данных
                rv = pkcs11.C_Sign(session, digest, Convert.ToUInt32(digest.Length), signature, ref signatureLen);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Инициализация проверки подписи по алгоритму ГОСТ Р 34.10-2012(512)
                rv = pkcs11.C_VerifyInit(session, ref signMechanism, pubKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                // Проверить подпись для данных
                rv = pkcs11.C_Verify(session, digest, Convert.ToUInt32(digest.Length), signature, Convert.ToUInt32(signature.Length));
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, privKeyId);
                if (rv != CKR.CKR_OK)
                    Assert.Fail(rv.ToString());

                rv = pkcs11.C_DestroyObject(session, pubKeyId);
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
