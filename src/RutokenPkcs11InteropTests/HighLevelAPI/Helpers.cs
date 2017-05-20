using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Net.Pkcs11Interop.HighLevelAPI;
using RutokenPkcs11Interop.Common;
using RutokenPkcs11Interop.HighLevelAPI.MechanismParams;

namespace RutokenPkcs11InteropTests.HighLevelAPI
{
    /// <summary>
    /// Helper methods for HighLevelAPI tests.
    /// </summary>
    public static class Helpers
    {
        /// <summary>
        /// Finds slot containing the token that matches criteria specified in Settings class
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <returns>Slot containing the token that matches criteria</returns>
        public static Slot GetUsableSlot(Pkcs11 pkcs11)
        {
            // Get list of available slots with token present
            List<Slot> slots = pkcs11.GetSlotList(true);

            Assert.IsNotNull(slots);
            Assert.IsTrue(slots.Count > 0);

            // First slot with token present is OK...
            Slot matchingSlot = slots[0];

            // ...unless there are matching criteria specified in Settings class
            if (Settings.TokenSerial != null || Settings.TokenLabel != null)
            {
                matchingSlot = null;

                foreach (Slot slot in slots)
                {
                    TokenInfo tokenInfo = null;

                    try
                    {
                        tokenInfo = slot.GetTokenInfo();
                    }
                    catch (Pkcs11Exception ex)
                    {
                        if (ex.RV != CKR.CKR_TOKEN_NOT_RECOGNIZED && ex.RV != CKR.CKR_TOKEN_NOT_PRESENT)
                            throw;
                    }

                    if (tokenInfo == null)
                        continue;

                    if (!string.IsNullOrEmpty(Settings.TokenSerial))
                        if (0 != string.Compare(Settings.TokenSerial, tokenInfo.SerialNumber, StringComparison.Ordinal))
                            continue;

                    if (!string.IsNullOrEmpty(Settings.TokenLabel))
                        if (0 != string.Compare(Settings.TokenLabel, tokenInfo.Label, StringComparison.Ordinal))
                            continue;

                    matchingSlot = slot;
                    break;
                }
            }

            Assert.IsTrue(matchingSlot != null, "Token matching criteria specified in Settings class is not present");
            return matchingSlot;
        }

        /// <summary>
        /// Generates symetric key.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <returns>Object handle</returns>
        public static ObjectHandle GenerateGostSymmetricKey(Session session)
        {
            // Шаблон для создания симметричного ключа ГОСТ 28147-89
            var objectAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.GostSecretKeyLabel),
                new ObjectAttribute(CKA.CKA_ID, Settings.GostSecretKeyId),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint) Extended_CKK.CKK_GOST28147),
                new ObjectAttribute(CKA.CKA_ENCRYPT, true),
                new ObjectAttribute(CKA.CKA_DECRYPT, true),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
                new ObjectAttribute((uint) Extended_CKA.CKA_GOST28147_PARAMS, Settings.Gost28147Parameters)
            };

            // Определяем механизм генерации ключа
            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOST28147_KEY_GEN);

            // Генерируем ключ
            return session.GenerateKey(mechanism, objectAttributes);
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <param name = 'publicKeyHandle' > Output parameter for public key object handle</param>
        /// <param name = 'privateKeyHandle' > Output parameter for private key object handle</param>
        public static void GenerateGostKeyPair(Session session, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle, string keyPairId)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            var publicKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.GostPublicKeyLabel),
                new ObjectAttribute(CKA.CKA_ID, keyPairId),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, false),
                new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            var privateKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.GostPrivateKeyLabel),
                new ObjectAttribute(CKA.CKA_ID, keyPairId),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
                new ObjectAttribute(CKA.CKA_DERIVE, true),
                new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters),
                new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411Parameters)
            };

            // Specify key generation mechanism
            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

            Assert.IsTrue(publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <param name = 'publicKeyHandle' > Output parameter for public key object handle</param>
        /// <param name = 'privateKeyHandle' > Output parameter for private key object handle</param>
        public static void GenerateGost512KeyPair(Session session, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle, string keyPairId)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            var publicKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.Gost512PublicKeyLabel),
                new ObjectAttribute(CKA.CKA_ID, keyPairId),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, false),
                new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            var privateKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.Gost512PrivateKeyLabel),
                new ObjectAttribute(CKA.CKA_ID, keyPairId),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
                new ObjectAttribute(CKA.CKA_DERIVE, true),
                new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters),
                new ObjectAttribute((uint) Extended_CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters)
            };

            // Specify key generation mechanism
            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

            Assert.IsTrue(publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для генерации пары ключей
        /// для подписи журнала по ГОСТ Р 34.10-2012
        /// </summary>
        /// <param name="session">Открытая сессия с токеном</param>
        /// <param name="publicKeyHandle">Хэндл публичного ключа</param>
        /// <param name="privateKeyHandle">Хэндл приватного ключа</param>
        public static void GenerateGost512JournalKeyPair(Session session, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012
            var publicKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, false),
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012
            var privateKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
            };

            // Определение механизма генерации ключей
            var mechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

            // Генерация ключевой пары
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

            Assert.IsTrue(publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <param name = 'publicKeyHandle' > Output parameter for public key object handle</param>
        /// <param name = 'privateKeyHandle' > Output parameter for private key object handle</param>
        /// <param name="keyPairId"></param>
        public static void GenerateRSAKeyPair(Session session, out ObjectHandle publicKeyHandle, out ObjectHandle privateKeyHandle, string keyPairId)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            var publicKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.RsaPublicKeyLabel),
                new ObjectAttribute(CKA.CKA_ID, keyPairId),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_ENCRYPT, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, false),
                new ObjectAttribute(CKA.CKA_MODULUS_BITS, Settings.RsaModulusBits)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            var privateKeyAttributes = new List<ObjectAttribute>()
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.RsaPrivateKeyLabel),
                new ObjectAttribute(CKA.CKA_ID, keyPairId),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                new ObjectAttribute(CKA.CKA_TOKEN, true),
                new ObjectAttribute(CKA.CKA_DECRYPT, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
            };

            // Specify key generation mechanism
            var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

            Assert.IsTrue(publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        public static void Derive_GostR3410_Key(Session session, ObjectHandle publicKeyHandle, ObjectHandle privateKeyHandle,
            byte[] ukm, out ObjectHandle derivedKeyHandle)
        {
            // Шаблон для создания ключа обмена
            var derivedKeyAttributes = new List<ObjectAttribute>
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.DerivedKeyLabel),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
                new ObjectAttribute(CKA.CKA_TOKEN, false),
                new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
                new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
                new ObjectAttribute(CKA.CKA_SENSITIVE, false)
            };

            // Получаем публичный ключ по его Id
            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };
            List<ObjectAttribute> publicKeyAttributes = session.GetAttributeValue(publicKeyHandle, attributes);

            // Определение параметров механизма наследования ключа
            var deriveMechanismParams =
                new CkGostR3410DeriveParams(
                    (uint)Extended_CKD.CKD_CPDIVERSIFY_KDF, publicKeyAttributes[0].GetValueAsByteArray(), ukm);

            // Определяем механизм наследования ключа
            var deriveMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeyHandle, derivedKeyAttributes);

            Assert.IsTrue(derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        public static void Derive_GostR3410_12_Key(Session session, ObjectHandle publicKeyHandle, ObjectHandle privateKeyHandle,
            byte[] ukm, out ObjectHandle derivedKeyHandle)
        {
            // Шаблон для создания ключа обмена
            var derivedKeyAttributes = new List<ObjectAttribute>
            {
                new ObjectAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                new ObjectAttribute(CKA.CKA_LABEL, Settings.DerivedKeyLabel),
                new ObjectAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147),
                new ObjectAttribute(CKA.CKA_TOKEN, false),
                new ObjectAttribute(CKA.CKA_MODIFIABLE, true),
                new ObjectAttribute(CKA.CKA_PRIVATE, true),
                new ObjectAttribute(CKA.CKA_EXTRACTABLE, true),
                new ObjectAttribute(CKA.CKA_SENSITIVE, false)
            };

            // Получаем публичный ключ по его Id
            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };
            List<ObjectAttribute> publicKeyAttributes = session.GetAttributeValue(publicKeyHandle, attributes);

            // Определение параметров механизма наследования ключа
            var deriveMechanismParams =
                new CkGostR3410_12_DeriveParams(
                    (uint)Extended_CKM.CKM_KDF_GOSTR3411_2012_256, publicKeyAttributes[0].GetValueAsByteArray(), ukm);

            // Определяем механизм наследования ключа
            Mechanism deriveMechanism = new Mechanism((uint)Extended_CKM.CKM_GOSTR3410_12_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeyHandle, derivedKeyAttributes);

            Assert.IsTrue(derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }
    }
}
