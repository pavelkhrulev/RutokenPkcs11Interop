using System;
using System.IO;
using NUnit.Framework;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI81;
using Net.Pkcs11Interop.LowLevelAPI81.MechanismParams;

using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Helpers;
using Net.RutokenPkcs11Interop.LowLevelAPI81.MechanismParams;
using Net.RutokenPkcs11Interop.LowLevelAPI81;

using NativeULong = System.UInt64;

namespace Net.RutokenPkcs11InteropTests.LowLevelAPI81
{
    public static class Helpers
    {
        /// <summary>
        /// Вспомогательная функция для поиска первого слота,
        /// содержащего установленный токен
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <returns>Слот, содержащий токен</returns>
        public static NativeULong GetUsableSlot(RutokenPkcs11Library pkcs11)
        {
            CKR rv = CKR.CKR_OK;

            // Получение списка слотов
            NativeULong slotCount = 0;
            rv = pkcs11.C_GetSlotList(true, null, ref slotCount);
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(slotCount > 0);

            NativeULong[] slotList = new NativeULong[slotCount];

            rv = pkcs11.C_GetSlotList(true, slotList, ref slotCount);
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            // Если критерии поиска не установлены, возвращаем первый слот,
            // содержащий установленный токен
            if (Settings.TokenSerial == null && Settings.TokenLabel == null)
                return slotList[0];

            NativeULong? matchingSlot = slotList[0];

            // Ищем токен в соответствии с установлеными критериями
            if (Settings.TokenSerial != null || Settings.TokenLabel != null)
            {
                matchingSlot = null;

                foreach (NativeULong slot in slotList)
                {
                    CK_TOKEN_INFO tokenInfo = new CK_TOKEN_INFO();
                    rv = pkcs11.C_GetTokenInfo(slot, ref tokenInfo);
                    if (rv != CKR.CKR_OK)
                    {
                        if (rv == CKR.CKR_TOKEN_NOT_RECOGNIZED || rv == CKR.CKR_TOKEN_NOT_PRESENT)
                            continue;
                        else
                            Assert.Fail(rv.ToString());
                    }

                    if (!string.IsNullOrEmpty(Settings.TokenSerial))
                        if (0 != string.Compare(Settings.TokenSerial, ConvertUtils.BytesToUtf8String(tokenInfo.SerialNumber, true), StringComparison.Ordinal))
                            continue;

                    if (!string.IsNullOrEmpty(Settings.TokenLabel))
                        if (0 != string.Compare(Settings.TokenLabel, ConvertUtils.BytesToUtf8String(tokenInfo.Label, true), StringComparison.Ordinal))
                            continue;

                    matchingSlot = slot;
                    break;
                }
            }

            Assert.IsTrue(matchingSlot != null, "Token matching criteria specified in Settings class is not present");
            return matchingSlot.Value;
        }

        /// <summary>
        /// Вспомогательная функция для генерации симметричного ключа по ГОСТ 28147
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='keyId'>Хэндл ключа</param>
        /// <returns>Return value of C_GenerateKey</returns>
        public static void GenerateGostSymmetricKey(RutokenPkcs11Library pkcs11, NativeULong session, ref NativeULong keyId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для создания симметричного ключа ГОСТ 28147-89
            var template = new CK_ATTRIBUTE[9];
            template[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            template[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.GostSecretKeyLabel);
            template[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, Settings.GostSecretKeyId);
            template[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
            template[4] = CkaUtils.CreateAttribute(CKA.CKA_ENCRYPT, true);
            template[5] = CkaUtils.CreateAttribute(CKA.CKA_DECRYPT, true);
            template[6] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            template[7] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            template[8] = CkaUtils.CreateAttribute(CKA.CKA_GOST28147_PARAMS, Settings.Gost28147Parameters);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((NativeULong)CKM.CKM_GOST28147_KEY_GEN);

            // Генерация секретного ключа ГОСТ 28147-89
            rv = pkcs11.C_GenerateKey(session, ref mechanism, template, Convert.ToUInt64(template.Length), ref keyId);

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < template.Length; i++)
            {
                UnmanagedMemory.Free(ref template[i].value);
                template[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(keyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для генерации асимметричных ключей по ГОСТ Р 34.10-2001
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='publicKeyId'>Хэндл публичного ключа</param>
        /// <param name='privateKeyId'>Хэндл приватного ключа</param>
        /// <param name="keyPairId">ID ключевой пары</param>
        /// <returns>Return value of C_GenerateKeyPair</returns>
        public static void GenerateGostKeyPair(RutokenPkcs11Library pkcs11, NativeULong session, ref NativeULong publicKeyId, ref NativeULong privateKeyId,
            string keyPairId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            var publicKeyTemplate = new CK_ATTRIBUTE[7];
            publicKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            publicKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.GostPublicKeyLabel);
            publicKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            publicKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410);
            publicKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            publicKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            publicKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters);

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            var privateKeyTemplate = new CK_ATTRIBUTE[9];
            privateKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            privateKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.GostPrivateKeyLabel);
            privateKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            privateKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410);
            privateKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            privateKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            privateKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_DERIVE, true);
            privateKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters);
            privateKeyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411Parameters);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((NativeULong)CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

            // Генерация ключевой пары
            rv = pkcs11.C_GenerateKeyPair(session, ref mechanism, publicKeyTemplate, Convert.ToUInt64(publicKeyTemplate.Length),
                privateKeyTemplate, Convert.ToUInt64(privateKeyTemplate.Length),
                ref publicKeyId, ref privateKeyId);

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < privateKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privateKeyTemplate[i].value);
                privateKeyTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < publicKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref publicKeyTemplate[i].value);
                publicKeyTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(publicKeyId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для генерации асимметричных ключей по ГОСТ Р 34.10-2012
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='publicKeyId'>Хэндл публичного ключа</param>
        /// <param name='privateKeyId'>Хэндл приватного ключа</param>
        /// <param name="keyPairId">ID ключевой пары</param>
        /// <returns>Return value of C_GenerateKeyPair</returns>
        public static void GenerateGost512KeyPair(RutokenPkcs11Library pkcs11, NativeULong session, ref NativeULong publicKeyId, ref NativeULong privateKeyId,
            string keyPairId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012
            var publicKeyTemplate = new CK_ATTRIBUTE[7];
            publicKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            publicKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.Gost512PublicKeyLabel);
            publicKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            publicKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (NativeULong)Extended_CKK.CKK_GOSTR3410_512);
            publicKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            publicKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            publicKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters);

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012
            var privateKeyTemplate = new CK_ATTRIBUTE[9];
            privateKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            privateKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.Gost512PrivateKeyLabel);
            privateKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            privateKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (NativeULong)Extended_CKK.CKK_GOSTR3410_512);
            privateKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            privateKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            privateKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_DERIVE, true);
            privateKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters);
            privateKeyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

            // Генерация ключевой пары
            rv = pkcs11.C_GenerateKeyPair(session, ref mechanism, publicKeyTemplate, Convert.ToUInt64(publicKeyTemplate.Length),
                privateKeyTemplate, Convert.ToUInt64(privateKeyTemplate.Length),
                ref publicKeyId, ref privateKeyId);

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < privateKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privateKeyTemplate[i].value);
                privateKeyTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < publicKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref publicKeyTemplate[i].value);
                publicKeyTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(publicKeyId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для генерации асимметричных ключей по ГОСТ Р 34.10-2012 для работы с журналом
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='publicKeyId'>Хэндл публичного ключа</param>
        /// <param name='privateKeyId'>Хэндл приватного ключа</param>
        /// <returns>Return value of C_GenerateKeyPair</returns>
        public static void GenerateGost512JournalKeyPair(RutokenPkcs11Library pkcs11, NativeULong session, ref NativeULong publicKeyId, ref NativeULong privateKeyId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012
            var publicKeyTemplate = new CK_ATTRIBUTE[5];
            publicKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            publicKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (NativeULong)Extended_CKK.CKK_GOSTR3410_512);
            publicKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            publicKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            publicKeyTemplate[4] = CkaUtils.CreateAttribute((NativeULong)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true);

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012
            var privateKeyTemplate = new CK_ATTRIBUTE[6];
            privateKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            privateKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (NativeULong)Extended_CKK.CKK_GOSTR3410_512);
            privateKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            privateKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            privateKeyTemplate[4] = CkaUtils.CreateAttribute((NativeULong)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true);
            privateKeyTemplate[5] = CkaUtils.CreateAttribute((NativeULong)Extended_CKA.CKA_VENDOR_KEY_CONFIRM_OP, false);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

            // Генерация ключевой пары
            rv = pkcs11.C_GenerateKeyPair(session, ref mechanism, publicKeyTemplate, Convert.ToUInt64(publicKeyTemplate.Length),
                privateKeyTemplate, Convert.ToUInt64(privateKeyTemplate.Length),
                ref publicKeyId, ref privateKeyId);

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < privateKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privateKeyTemplate[i].value);
                privateKeyTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < privateKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privateKeyTemplate[i].value);
                privateKeyTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(publicKeyId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для генерации асимметричных ключей по ГОСТ Р 34.10-2012 для работы с PIN PAD
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='publicKeyId'>Хэндл публичного ключа</param>
        /// <param name='privateKeyId'>Хэндл приватного ключа</param>
        /// <param name="keyPairId">ID ключевой пары</param>
        /// <returns>Return value of C_GenerateKeyPair</returns>
        public static void GenerateGost512PINPadKeyPair(RutokenPkcs11Library pkcs11, NativeULong session, ref NativeULong publicKeyId, ref NativeULong privateKeyId,
            string keyPairId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012
            var publicKeyTemplate = new CK_ATTRIBUTE[8];
            publicKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            publicKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.Gost512PublicKeyLabel);
            publicKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            publicKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (NativeULong)Extended_CKK.CKK_GOSTR3410_512);
            publicKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            publicKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            publicKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters);
            publicKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters);

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012
            var privateKeyTemplate = new CK_ATTRIBUTE[10];
            privateKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            privateKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.Gost512PrivateKeyLabel);
            privateKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            privateKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (NativeULong)Extended_CKK.CKK_GOSTR3410_512);
            privateKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            privateKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            privateKeyTemplate[6] = CkaUtils.CreateAttribute((NativeULong)Extended_CKA.CKA_VENDOR_KEY_CONFIRM_OP, true);
            privateKeyTemplate[7] = CkaUtils.CreateAttribute((NativeULong)Extended_CKA.CKA_VENDOR_KEY_PIN_ENTER, false);
            privateKeyTemplate[8] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters);
            privateKeyTemplate[9] = CkaUtils.CreateAttribute(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

            // Генерация ключевой пары
            rv = pkcs11.C_GenerateKeyPair(session, ref mechanism, publicKeyTemplate, Convert.ToUInt64(publicKeyTemplate.Length),
                privateKeyTemplate, Convert.ToUInt64(privateKeyTemplate.Length),
                ref publicKeyId, ref privateKeyId);

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < privateKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privateKeyTemplate[i].value);
                privateKeyTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < privateKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privateKeyTemplate[i].value);
                privateKeyTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(publicKeyId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для генерации асимметричных RSA ключей
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='publicKeyId'>Хэндл публичного ключа</param>
        /// <param name='privateKeyId'>Хэндл приватного ключа</param>
        /// <param name="keyPairId">ID ключевой пары</param>
        /// <returns>Return value of C_GenerateKeyPair</returns>
        public static void GenerateRSAKeyPair(RutokenPkcs11Library pkcs11, NativeULong session, ref NativeULong publicKeyId, ref NativeULong privateKeyId,
            string keyPairId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для генерации открытого ключа RSA
            var publicKeyTemplate = new CK_ATTRIBUTE[8];
            publicKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            publicKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.RsaPublicKeyLabel);
            publicKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            publicKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
            publicKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            publicKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_ENCRYPT, true);
            publicKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            publicKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_MODULUS_BITS, Settings.RsaModulusBits);

            // Шаблон для генерации закрытого ключа RSA
            var privateKeyTemplate = new CK_ATTRIBUTE[7];
            privateKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            privateKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.RsaPrivateKeyLabel);
            privateKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            privateKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA);
            privateKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            privateKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_DECRYPT, true);
            privateKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

            // Генерация ключевой пары
            rv = pkcs11.C_GenerateKeyPair(session, ref mechanism, publicKeyTemplate, Convert.ToUInt64(publicKeyTemplate.Length),
                privateKeyTemplate, Convert.ToUInt64(privateKeyTemplate.Length),
                ref publicKeyId, ref privateKeyId);

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < privateKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privateKeyTemplate[i].value);
                privateKeyTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < publicKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref publicKeyTemplate[i].value);
                publicKeyTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(publicKeyId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для выработки ключа по ГОСТ 34.10-2001
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='publicKeyId'>Хэндл публичного ключа</param>
        /// <param name='privateKeyId'>Хэндл приватного ключа</param>
        /// <param name="ukm"></param>
        /// <param name="derivedKeyId">ID вырабатанного ключа</param>
        /// <returns>Return value of C_DeriveKey</returns>
        public static void Derive_GostR3410_Key(RutokenPkcs11Library pkcs11, NativeULong session, NativeULong publicKeyId, NativeULong privateKeyId,
            byte[] ukm, ref NativeULong derivedKeyId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для создания ключа обмена
            var derivedKeyTemplate = new CK_ATTRIBUTE[8];
            derivedKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            derivedKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.DerivedKeyLabel);
            derivedKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
            derivedKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
            derivedKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
            derivedKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            derivedKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
            derivedKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

            // Получаем публичный ключ по его Id
            var valueTemplate = new CK_ATTRIBUTE[1];
            valueTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_VALUE);
            valueTemplate[0].value = UnmanagedMemory.Allocate(Settings.GOST_3410_KEY_SIZE);
            valueTemplate[0].valueLen = Convert.ToUInt64(Settings.GOST_3410_KEY_SIZE);

            rv = pkcs11.C_GetAttributeValue(session, publicKeyId, valueTemplate, Convert.ToUInt64(valueTemplate.Length));
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            byte[] publicKey = UnmanagedMemory.Read(valueTemplate[0].value, Convert.ToInt32(valueTemplate[0].valueLen));

            // Определяем параметры механизма выработки ключа
            var deriveMechanismParams = new CK_GOSTR3410_DERIVE_PARAMS
            {
                Kdf = (NativeULong) CKD.CKD_CPDIVERSIFY_KDF,
                PublicData = UnmanagedMemory.Allocate(publicKey.Length),
                PublicDataLen = Convert.ToUInt64(publicKey.Length),
                UKM = UnmanagedMemory.Allocate(ukm.Length),
                UKMLen = Convert.ToUInt64(ukm.Length)
            };
            UnmanagedMemory.Write(deriveMechanismParams.PublicData, publicKey);
            UnmanagedMemory.Write(deriveMechanismParams.UKM, ukm);

            // Определяем механизм выработки ключа
            CK_MECHANISM deriveMechanism = CkmUtils.CreateMechanism(CKM.CKM_GOSTR3410_DERIVE, deriveMechanismParams);

            // Выработка ключа согласно установленному выше шаблону
            rv = pkcs11.C_DeriveKey(session, ref deriveMechanism, privateKeyId, derivedKeyTemplate,
                Convert.ToUInt64(derivedKeyTemplate.Length), ref derivedKeyId);

            // Очистка памяти, выделенной под различные параметры
            UnmanagedMemory.Free(ref valueTemplate[0].value);
            valueTemplate[0].valueLen = 0;

            UnmanagedMemory.Free(ref deriveMechanismParams.PublicData);
            deriveMechanismParams.PublicDataLen = 0;

            UnmanagedMemory.Free(ref deriveMechanismParams.UKM);
            deriveMechanismParams.UKMLen = 0;

            UnmanagedMemory.Free(ref deriveMechanism.Parameter);
            deriveMechanism.ParameterLen = 0;

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < valueTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref valueTemplate[i].value);
                valueTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < derivedKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref derivedKeyTemplate[i].value);
                derivedKeyTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(derivedKeyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для выработки ключа по ГОСТ 34.10-2012
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Сессия пользователя</param>
        /// <param name='publicKeyId'>Хэндл публичного ключа</param>
        /// <param name='privateKeyId'>Хэндл приватного ключа</param>
        /// <param name="ukm"></param>
        /// <param name="derivedKeyId">ID вырабатанного ключа</param>
        /// <returns>Return value of C_DeriveKey</returns>
        public static void Derive_GostR3410_12_Key(RutokenPkcs11Library pkcs11, NativeULong session, NativeULong publicKeyId, NativeULong privateKeyId,
            byte[] ukm, ref NativeULong derivedKeyId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для создания ключа обмена
            var derivedKeyTemplate = new CK_ATTRIBUTE[8];
            derivedKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            derivedKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.DerivedKeyLabel);
            derivedKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147);
            derivedKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
            derivedKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
            derivedKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            derivedKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
            derivedKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

            // Получаем публичный ключ по его Id
            CK_ATTRIBUTE[] valueTemplate = new CK_ATTRIBUTE[1];
            valueTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_VALUE);
            valueTemplate[0].value = UnmanagedMemory.Allocate(Settings.GOST_3410_12_512_KEY_SIZE);
            valueTemplate[0].valueLen = Convert.ToUInt64(Settings.GOST_3410_12_512_KEY_SIZE);

            rv = pkcs11.C_GetAttributeValue(session, publicKeyId, valueTemplate, Convert.ToUInt64(valueTemplate.Length));
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());
            byte[] publicKey = UnmanagedMemory.Read(valueTemplate[0].value, Convert.ToInt32(valueTemplate[0].valueLen));


            // Определяем параметры механизма выработки ключа
            var deriveMechanismParams = new CK_GOSTR3410_12_DERIVE_PARAMS
            {
                Kdf = (NativeULong) Extended_CKM.CKM_KDF_GOSTR3411_2012_256,
                PublicDataLen = Convert.ToUInt64(publicKey.Length),
                PublicData = new byte[Settings.GOST_3410_12_512_KEY_SIZE],
                UKMLen = Convert.ToUInt64(ukm.Length),
                UKM = new byte[Settings.UKM_LENGTH],
            };
            Array.Copy(publicKey, deriveMechanismParams.PublicData, publicKey.Length);
            Array.Copy(ukm, deriveMechanismParams.UKM, ukm.Length);

            // Определяем механизм выработки ключа
            CK_MECHANISM deriveMechanism = CkmUtils.CreateMechanism((CKM) Extended_CKM.CKM_GOSTR3410_12_DERIVE, deriveMechanismParams);

            // Выработка ключа согласно установленному выше шаблону
            rv = pkcs11.C_DeriveKey(session, ref deriveMechanism, privateKeyId, derivedKeyTemplate,
                Convert.ToUInt64(derivedKeyTemplate.Length), ref derivedKeyId);

            // Очистка памяти, выделенной под различные параметры
            UnmanagedMemory.Free(ref deriveMechanism.Parameter);
            deriveMechanism.ParameterLen = 0;

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < valueTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref valueTemplate[i].value);
                valueTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < derivedKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref derivedKeyTemplate[i].value);
                derivedKeyTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(derivedKeyId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для шифрования данных по алгоритму ГОСТ 28147-89
        /// с зацеплением
        /// </summary>
        /// <param name="pkcs11">Initialized PKCS11 wrapper</param>
        /// <param name="session">Сессия пользователя</param>
        /// <param name="data">Данные для шифрования</param>
        /// <param name="initVector">Синхропосылка</param>
        /// <param name="keyId">Ключ для шифрования</param>
        /// <returns>Зашифрованные данные</returns>
        public static byte[] CBC_Gost28147_89_Encrypt(RutokenPkcs11Library pkcs11, NativeULong session, byte[] data,
            byte[] initVector, NativeULong keyId)
        {
            // Дополняем данные по ISO 10126
            byte[] dataWithPadding = ISO_10126_Padding.Pad(data, Settings.GOST28147_89_BLOCK_SIZE);

            byte[] round = new byte[Settings.GOST28147_89_BLOCK_SIZE];
            Buffer.BlockCopy(initVector, 0, round, 0, initVector.Length);

            using (var ms = new MemoryStream())
            {
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_GOST28147_ECB);

                for (var i = 0; i < dataWithPadding.Length / Settings.GOST28147_89_BLOCK_SIZE; i++)
                {
                    CKR rv = CKR.CKR_OK;

                    byte[] currentData = new byte[Settings.GOST28147_89_BLOCK_SIZE];
                    Buffer.BlockCopy(dataWithPadding, i * Settings.GOST28147_89_BLOCK_SIZE,
                        currentData, 0, currentData.Length);
                    byte[] block = round.Xor(currentData);

                    // Инициализация операции шифрования
                    rv = pkcs11.C_EncryptInit(session, ref mechanism, keyId);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Получение зашифрованного блока данных
                    byte[] encryptedBlock = new byte[block.Length];
                    NativeULong blockLength = Convert.ToUInt64(block.Length);
                    rv = pkcs11.C_Encrypt(session, block, Convert.ToUInt64(block.Length), encryptedBlock, ref blockLength);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    Buffer.BlockCopy(encryptedBlock, 0, round, 0, encryptedBlock.Length);
                    ms.Write(encryptedBlock, 0, encryptedBlock.Length);
                }

                return ms.ToArray();
            }
        }

        /// <summary>
        /// Вспомогательная функция для расшифрования данных по алгоритму ГОСТ 28147-89
        /// с зацеплением
        /// </summary>
        /// <param name="pkcs11">Initialized PKCS11 wrapper</param>
        /// <param name="session">Cессия пользователя</param>
        /// <param name="data">Зашифрованные данные</param>
        /// <param name="initVector">Синхропосылка</param>
        /// <param name="keyId">Ключ для расшифрования</param>
        /// <returns>Расшифрованные данные</returns>
        public static byte[] CBC_Gost28147_89_Decrypt(RutokenPkcs11Library pkcs11, NativeULong session,
            byte[] data, byte[] initVector, NativeULong keyId)
        {
            byte[] round = new byte[Settings.GOST28147_89_BLOCK_SIZE];
            Buffer.BlockCopy(initVector, 0, round, 0, initVector.Length);

            using (var ms = new MemoryStream())
            {
                CK_MECHANISM mechanism = CkmUtils.CreateMechanism(CKM.CKM_GOST28147_ECB);

                for (var i = 0; i < data.Length / Settings.GOST28147_89_BLOCK_SIZE; i++)
                {
                    CKR rv = CKR.CKR_OK;

                    byte[] currentData = new byte[Settings.GOST28147_89_BLOCK_SIZE];
                    Buffer.BlockCopy(data, i * Settings.GOST28147_89_BLOCK_SIZE,
                        currentData, 0, currentData.Length);

                    // Инициализация операции расшифрования
                    rv = pkcs11.C_DecryptInit(session, ref mechanism, keyId);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    // Получение расшифрованного блока данных
                    byte[] decryptedBlock = new byte[currentData.Length];
                    NativeULong blockLength = Convert.ToUInt64(currentData.Length);
                    rv = pkcs11.C_Decrypt(session, currentData, Convert.ToUInt64(currentData.Length),
                        decryptedBlock, ref blockLength);
                    if (rv != CKR.CKR_OK)
                        Assert.Fail(rv.ToString());

                    byte[] decryptedRound = round.Xor(decryptedBlock);
                    Buffer.BlockCopy(currentData, 0, round, 0, currentData.Length);

                    ms.Write(decryptedRound, 0, decryptedRound.Length);
                }

                byte[] decryptedData = ms.ToArray();

                // Снимаем дополнение данных
                return ISO_10126_Padding.Unpad(decryptedData);
            }
        }

        /// <summary>
        /// Вспомогательная функция для импорта сертификата
        /// </summary>
        /// <param name="pkcs11">Initialized PKCS11 wrapper</param>
        /// <param name="session">Cессия пользователя</param>
        /// <param name="certificateDer">Сертификат в формате DER</param>
        /// <param name="certificateId">Хэндл сертификата</param>
        /// <returns></returns>
        public static void PKI_ImportCertificate(RutokenPkcs11Library pkcs11, NativeULong session, byte[] certificateDer, ref NativeULong certificateId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для импорта сертификата
            CK_ATTRIBUTE[] certificateTemplate = new CK_ATTRIBUTE[7];
            certificateTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_VALUE, certificateDer);
            certificateTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE);
            certificateTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, Settings.GostKeyPairId1);
            certificateTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            certificateTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            certificateTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509);

            NativeULong tokenUserCertificate = 1;
            certificateTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_CERTIFICATE_CATEGORY, tokenUserCertificate);

            // Создание сертификата на токене
            rv = pkcs11.C_CreateObject(session, certificateTemplate, Convert.ToUInt64(certificateTemplate.Length), ref certificateId);

            // Очистка памяти, выделенной под аттрибуты
            for (int i = 0; i < certificateTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref certificateTemplate[i].value);
                certificateTemplate[i].valueLen = 0;
            }

            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(certificateId != CK.CK_INVALID_HANDLE);
        }
    }
}
