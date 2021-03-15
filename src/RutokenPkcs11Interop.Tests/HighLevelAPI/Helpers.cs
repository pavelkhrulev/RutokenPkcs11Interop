using System;
using System.Collections.Generic;
using System.IO;
using Net.Pkcs11Interop.Common;
using NUnit.Framework;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.RutokenPkcs11Interop.Common;
using Net.RutokenPkcs11Interop.Helpers;
using Net.RutokenPkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;

namespace Net.RutokenPkcs11InteropTests.HighLevelAPI
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
        public static IRutokenSlot GetUsableSlot(IRutokenPkcs11Library pkcs11)
        {
            // Get list of available slots with token present
            List<IRutokenSlot> slots = pkcs11.GetRutokenSlotList(SlotsType.WithTokenPresent);

            Assert.IsNotNull(slots);
            Assert.IsTrue(slots.Count > 0);

            // First slot with token present is OK...
            IRutokenSlot matchingSlot = slots[0];

            // ...unless there are matching criteria specified in Settings class
            if (Settings.TokenSerial != null || Settings.TokenLabel != null)
            {
                matchingSlot = null;

                foreach (IRutokenSlot slot in slots)
                {
                    ITokenInfo tokenInfo = null;

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
        /// Generates Gost 28147-89 symetric key.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <returns>Object handle</returns>
        public static IObjectHandle GenerateGost28147_89Key(ISession session)
        {
            // Шаблон для создания симметричного ключа ГОСТ 28147-89
            var objectAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.Gost28147_89KeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Settings.Gost28147_89KeyId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOST28147_PARAMS, Settings.Gost28147Parameters)
            };

            // Определяем механизм генерации ключа
            var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_KEY_GEN);

            // Генерируем ключ
            return session.GenerateKey(mechanism, objectAttributes);
        }

        public enum KeyDestenation
        {
            ForEncDec,
            ForSigVer
        }

        /// <summary>
        /// Generates Kuznechik symetric key.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <returns>Object handle</returns>
        public static IObjectHandle GenerateKuznechikKey(ISession session, KeyDestenation dest = KeyDestenation.ForEncDec)
        {
            // Шаблон для создания симметричного ключа Кузнечик
            var objectAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.KuznechikKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Settings.KuznechikKeyId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (CKK) Extended_CKK.CKK_KUZNECHIK),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, dest == KeyDestenation.ForEncDec),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, dest == KeyDestenation.ForEncDec),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, dest == KeyDestenation.ForSigVer),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, dest == KeyDestenation.ForSigVer),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            };

            // Определяем механизм генерации ключа
            var mechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_KUZNECHIK_KEY_GEN);

            // Генерируем ключ
            return session.GenerateKey(mechanism, objectAttributes);
        }

        /// <summary>
        /// Generates Magma symetric key.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <returns>Object handle</returns>
        public static IObjectHandle GenerateMagmaKey(ISession session, KeyDestenation dest = KeyDestenation.ForEncDec)
        {
            // Шаблон для создания симметричного ключа Кузнечик
            var objectAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.MagmaLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, Settings.MagmaKeyId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (CKK) Extended_CKK.CKK_MAGMA),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, dest == KeyDestenation.ForEncDec),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, dest == KeyDestenation.ForEncDec),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SIGN, dest == KeyDestenation.ForSigVer),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_VERIFY, dest == KeyDestenation.ForSigVer),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            };

            // Определяем механизм генерации ключа
            var mechanism = Settings.Factories.MechanismFactory.Create((CKM)Extended_CKM.CKM_MAGMA_KEY_GEN);

            // Генерируем ключ
            return session.GenerateKey(mechanism, objectAttributes);
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name = 'session' > Read - write session with user logged in</param>
        /// <param name = 'publicKeyHandle' > Output parameter for public key object handle</param>
        /// <param name = 'privateKeyHandle' > Output parameter for private key object handle</param>
        public static void GenerateGostKeyPair(ISession session, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle, string keyPairId)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            var publicKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.GostPublicKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            var privateKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.GostPrivateKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOSTR3410),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411Parameters)
            };

            // Specify key generation mechanism
            var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

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
        public static void GenerateGost512KeyPair(ISession session, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle, string keyPairId)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            var publicKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.Gost512PublicKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            var privateKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.Gost512PrivateKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DERIVE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters)
            };

            // Specify key generation mechanism
            var mechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

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
        public static void GenerateGost512JournalKeyPair(ISession session, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012
            var publicKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                Settings.Factories.ObjectAttributeFactory.Create((uint)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012
            var privateKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                Settings.Factories.ObjectAttributeFactory.Create((uint)Extended_CKA.CKA_VENDOR_KEY_JOURNAL, true),
                Settings.Factories.ObjectAttributeFactory.Create((uint)Extended_CKA.CKA_VENDOR_KEY_CONFIRM_OP, false)
            };

            // Определение механизма генерации ключей
            var mechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

            // Генерация ключевой пары
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

            Assert.IsTrue(publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для генерации пары ключей по ГОСТ Р 34.10-2012
        /// </summary>
        /// <param name="session">Открытая сессия с токеном</param>
        /// <param name="publicKeyHandle">Хэндл публичного ключа</param>
        /// <param name="privateKeyHandle">Хэндл приватного ключа</param>
        /// <param name="keyPairId">ID ключевой пары</param>
        public static void GenerateGost512PINPadPair(
            ISession session, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle, string keyPairId)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012
            var publicKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.Gost512PublicKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012
            var privateKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.Gost512PrivateKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                Settings.Factories.ObjectAttributeFactory.Create((uint)Extended_CKA.CKA_VENDOR_KEY_CONFIRM_OP, true),
                Settings.Factories.ObjectAttributeFactory.Create((uint)Extended_CKA.CKA_VENDOR_KEY_PIN_ENTER, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters)
            };

            // Определение механизма генерации ключей
            var mechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

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
        public static void GenerateRSAKeyPair(ISession session, out IObjectHandle publicKeyHandle, out IObjectHandle privateKeyHandle, string keyPairId)
        {
            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            var publicKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.RsaPublicKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ENCRYPT, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, Settings.RsaModulusBits)
            };

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            var privateKeyAttributes = new List<IObjectAttribute>()
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.RsaPrivateKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, keyPairId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_DECRYPT, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
            };

            // Specify key generation mechanism
            var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_RSA_PKCS_KEY_PAIR_GEN);

            // Generate key pair
            session.GenerateKeyPair(mechanism, publicKeyAttributes, privateKeyAttributes, out publicKeyHandle, out privateKeyHandle);

            Assert.IsTrue(publicKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
            Assert.IsTrue(privateKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        public static void Derive_GostR3410_Key(ISession session, IObjectHandle publicKeyHandle, IObjectHandle privateKeyHandle,
            byte[] ukm, out IObjectHandle derivedKeyHandle)
        {
            // Шаблон для создания ключа обмена
            var derivedKeyAttributes = new List<IObjectAttribute>
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.DerivedKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false)
            };

            // Получаем публичный ключ по его Id
            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };
            List<IObjectAttribute> publicKeyAttributes = session.GetAttributeValue(publicKeyHandle, attributes);

            // Определение параметров механизма наследования ключа
            var deriveMechanismParams =
                Settings.Factories.MechanismParamsFactory.CreateCkGostR3410DeriveParams(
                    (ulong) CKD.CKD_CPDIVERSIFY_KDF, publicKeyAttributes[0].GetValueAsByteArray(), ukm);

            // Определяем механизм наследования ключа
            var deriveMechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOSTR3410_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeyHandle, derivedKeyAttributes);

            Assert.IsTrue(derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        public static void Derive_GostR3410_12_Key(ISession session, IObjectHandle publicKeyHandle, IObjectHandle privateKeyHandle,
            byte[] ukm, out IObjectHandle derivedKeyHandle)
        {
            // Шаблон для создания ключа обмена
            var derivedKeyAttributes = new List<IObjectAttribute>
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_LABEL, Settings.DerivedKeyLabel),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GOST28147),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_MODIFIABLE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_SENSITIVE, false)
            };

            // Получаем публичный ключ по его Id
            var attributes = new List<CKA>
            {
                CKA.CKA_VALUE
            };
            List<IObjectAttribute> publicKeyAttributes = session.GetAttributeValue(publicKeyHandle, attributes);

            // Определение параметров механизма наследования ключа
            var deriveMechanismParams =
                Settings.Factories.RutokenMechanismParamsFactory.CreateCkGostR3410_12_DeriveParams(
                    (ulong) Extended_CKD.CKD_KDF_GOSTR3411_2012_256, publicKeyAttributes[0].GetValueAsByteArray(), ukm);

            // Определяем механизм наследования ключа
            IMechanism deriveMechanism = Settings.Factories.MechanismFactory.Create((CKM) Extended_CKM.CKM_GOSTR3410_12_DERIVE, deriveMechanismParams);

            // Наследуем ключ
            derivedKeyHandle = session.DeriveKey(deriveMechanism, privateKeyHandle, derivedKeyAttributes);

            Assert.IsTrue(derivedKeyHandle.ObjectId != CK.CK_INVALID_HANDLE);
        }

        /// <summary>
        /// Вспомогательная функция для шифрования данных по алгоритму ГОСТ 28147-89
        /// с зацеплением
        /// </summary>
        /// <param name="session">Текущая сессия</param>
        /// <param name="data">Данные для шифрования</param>
        /// <param name="initVector">Синхропосылка</param>
        /// <param name="keyId">Ключ для шифрования</param>
        /// <returns>Зашифрованные данные</returns>
        public static byte[] CBC_Gost28147_89_Encrypt(ISession session, byte[] data,
            byte[] initVector, IObjectHandle keyId)
        {
            // Дополняем данные по ISO 10126
            byte[] dataWithPadding = ISO_10126_Padding.Pad(data, Settings.GOST28147_89_BLOCK_SIZE);

            byte[] round = new byte[Settings.GOST28147_89_BLOCK_SIZE];
            Buffer.BlockCopy(initVector, 0, round, 0, initVector.Length);

            using (var ms = new MemoryStream())
            {
                var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_ECB);

                for (var i = 0; i < dataWithPadding.Length / Settings.GOST28147_89_BLOCK_SIZE; i++)
                {
                    byte[] currentData = new byte[Settings.GOST28147_89_BLOCK_SIZE];
                    Buffer.BlockCopy(dataWithPadding, i * Settings.GOST28147_89_BLOCK_SIZE,
                        currentData, 0, currentData.Length);
                    byte[] block = round.Xor(currentData);

                    // Получение зашифрованного блока данных
                    byte[] encryptedBlock = session.Encrypt(mechanism, keyId, block);

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
        /// <param name="session">Текущая сессия</param>
        /// <param name="data">Зашифрованные данные</param>
        /// <param name="initVector">Синхропосылка</param>
        /// <param name="keyId">Ключ для расшифрования</param>
        /// <returns>Расшифрованные данные</returns>
        public static byte[] CBC_Gost28147_89_Decrypt(ISession session, byte[] data,
            byte[] initVector, IObjectHandle keyId)
        {
            byte[] round = new byte[Settings.GOST28147_89_BLOCK_SIZE];
            Buffer.BlockCopy(initVector, 0, round, 0, initVector.Length);

            using (var ms = new MemoryStream())
            {
                var mechanism = Settings.Factories.MechanismFactory.Create(CKM.CKM_GOST28147_ECB);

                for (var i = 0; i < data.Length / Settings.GOST28147_89_BLOCK_SIZE; i++)
                {
                    byte[] currentData = new byte[Settings.GOST28147_89_BLOCK_SIZE];
                    Buffer.BlockCopy(data, i * Settings.GOST28147_89_BLOCK_SIZE,
                        currentData, 0, currentData.Length);

                    // Получение расшифрованного блока данных
                    byte[] decryptedBlock = session.Decrypt(mechanism, keyId, currentData);

                    byte[] decryptedRound = round.Xor(decryptedBlock);
                    Buffer.BlockCopy(currentData, 0, round, 0, currentData.Length);

                    ms.Write(decryptedRound, 0, decryptedRound.Length);
                }

                byte[] decryptedData = ms.ToArray();

                // Снимаем дополнение данных
                return ISO_10126_Padding.Unpad(decryptedData);
            }
        }

        public static void PKI_ImportCertificate(ISession session, byte[] certificateDer, out IObjectHandle certificate, string certId)
        {
            // Шаблон для импорта сертификата
            var certificateAttributes = new List<IObjectAttribute>
            {
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_VALUE, certificateDer),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, certId),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_PRIVATE, false),
                Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509),
            };
            uint tokenUserCertificate = 1;
            certificateAttributes.Add(Settings.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_CATEGORY, tokenUserCertificate));

            // Создание сертификата на токене
            certificate = session.CreateObject(certificateAttributes);

            Assert.IsTrue(certificate.ObjectId != CK.CK_INVALID_HANDLE);
        }
    }
}
