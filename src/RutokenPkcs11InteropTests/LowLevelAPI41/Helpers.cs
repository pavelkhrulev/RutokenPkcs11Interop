using System;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.LowLevelAPI41;
using Net.Pkcs11Interop.LowLevelAPI41.MechanismParams;
using NUnit.Framework;
using RutokenPkcs11Interop;
using RutokenPkcs11Interop.LowLevelAPI41.MechanismParams;

namespace RutokenPkcs11InteropTests.LowLevelAPI41
{
    public static class Helpers
    {
        /// <summary>
        /// Finds slot containing the token that matches criteria specified in Settings class
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <returns>Slot containing the token that matches criteria</returns>
        public static uint GetUsableSlot(Pkcs11 pkcs11)
        {
            CKR rv = CKR.CKR_OK;

            // Get list of available slots with token present
            uint slotCount = 0;
            rv = pkcs11.C_GetSlotList(true, null, ref slotCount);
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            Assert.IsTrue(slotCount > 0);

            uint[] slotList = new uint[slotCount];

            rv = pkcs11.C_GetSlotList(true, slotList, ref slotCount);
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            // Return first slot with token present when both TokenSerial and TokenLabel are null...
            if (Settings.TokenSerial == null && Settings.TokenLabel == null)
                return slotList[0];

            // First slot with token present is OK...
            uint? matchingSlot = slotList[0];

            // ...unless there are matching criteria specified in Settings class
            if (Settings.TokenSerial != null || Settings.TokenLabel != null)
            {
                matchingSlot = null;

                foreach (uint slot in slotList)
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
        /// Generates symetric key.
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <param name='keyId'>Output parameter for key object handle</param>
        /// <returns>Return value of C_GenerateKey</returns>
        public static CKR GenerateGostSymmetricKey(Pkcs11 pkcs11, uint session, ref uint keyId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для создания симметричного ключа ГОСТ 28147-89
            CK_ATTRIBUTE[] template = new CK_ATTRIBUTE[9];
            template[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            template[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.GostSecretKeyLabel);
            template[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, Settings.GostSecretKeyId);
            template[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147);
            template[4] = CkaUtils.CreateAttribute(CKA.CKA_ENCRYPT, true);
            template[5] = CkaUtils.CreateAttribute(CKA.CKA_DECRYPT, true);
            template[6] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            template[7] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            template[8] = CkaUtils.CreateAttribute((uint)Extended_CKA.CKA_GOST28147_PARAMS, Settings.Gost28147Parameters);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOST28147_KEY_GEN);

            // Генерация секретного ключа ГОСТ 28147-89
            rv = pkcs11.C_GenerateKey(session, ref mechanism, template, Convert.ToUInt32(template.Length), ref keyId);

            // In LowLevelAPI we have to free unmanaged memory taken by attributes
            for (int i = 0; i < template.Length; i++)
            {
                UnmanagedMemory.Free(ref template[i].value);
                template[i].valueLen = 0;
            }

            return rv;
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <param name='pubKeyId'>Output parameter for public key object handle</param>
        /// <param name='privKeyId'>Output parameter for private key object handle</param>
        /// <returns>Return value of C_GenerateKeyPair</returns>
        public static CKR GenerateGostKeyPair(Pkcs11 pkcs11, uint session, ref uint pubKeyId, ref uint privKeyId,
            string keyPairId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2001
            CK_ATTRIBUTE[] pubKeyTemplate = new CK_ATTRIBUTE[7];
            pubKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            pubKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.GostPublicKeyLabel);
            pubKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            pubKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410);
            pubKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            pubKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            pubKeyTemplate[6] = CkaUtils.CreateAttribute((uint)Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters);

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2001
            CK_ATTRIBUTE[] privKeyTemplate = new CK_ATTRIBUTE[9];
            privKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            privKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.GostPrivateKeyLabel);
            privKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, keyPairId);
            privKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410);
            privKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            privKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            privKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_DERIVE, true);
            privKeyTemplate[7] = CkaUtils.CreateAttribute((uint)Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410Parameters);
            privKeyTemplate[8] = CkaUtils.CreateAttribute((uint)Extended_CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411Parameters);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3410_KEY_PAIR_GEN);

            // Генерация ключевой пары
            rv = pkcs11.C_GenerateKeyPair(session, ref mechanism, pubKeyTemplate, Convert.ToUInt32(pubKeyTemplate.Length),
                privKeyTemplate, Convert.ToUInt32(privKeyTemplate.Length),
                ref pubKeyId, ref privKeyId);

            // In LowLevelAPI we have to free unmanaged memory taken by attributes
            for (int i = 0; i < privKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privKeyTemplate[i].value);
                privKeyTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < pubKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref pubKeyTemplate[i].value);
                pubKeyTemplate[i].valueLen = 0;
            }

            return rv;
        }

        /// <summary>
        /// Generates asymetric key pair.
        /// </summary>
        /// <param name='pkcs11'>Initialized PKCS11 wrapper</param>
        /// <param name='session'>Read-write session with user logged in</param>
        /// <param name='pubKeyId'>Output parameter for public key object handle</param>
        /// <param name='privKeyId'>Output parameter for private key object handle</param>
        /// <returns>Return value of C_GenerateKeyPair</returns>
        public static CKR GenerateGost512KeyPair(Pkcs11 pkcs11, uint session, ref uint pubKeyId, ref uint privKeyId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для генерации открытого ключа ГОСТ Р 34.10-2012
            CK_ATTRIBUTE[] pubKeyTemplate = new CK_ATTRIBUTE[7];
            pubKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PUBLIC_KEY);
            pubKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.Gost512PublicKeyLabel);
            pubKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, Settings.Gost512KeyPairId);
            pubKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512);
            pubKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            pubKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, false);
            pubKeyTemplate[6] = CkaUtils.CreateAttribute((uint)Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters);

            // Шаблон для генерации закрытого ключа ГОСТ Р 34.10-2012
            CK_ATTRIBUTE[] privKeyTemplate = new CK_ATTRIBUTE[9];
            privKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY);
            privKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.Gost512PrivateKeyLabel);
            privKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_ID, Settings.Gost512KeyPairId);
            privKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOSTR3410_512);
            privKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, true);
            privKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            privKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_DERIVE, true);
            privKeyTemplate[7] = CkaUtils.CreateAttribute((uint)Extended_CKA.CKA_GOSTR3410_PARAMS, Settings.GostR3410_512_Parameters);
            privKeyTemplate[8] = CkaUtils.CreateAttribute((uint)Extended_CKA.CKA_GOSTR3411_PARAMS, Settings.GostR3411_512_Parameters);

            CK_MECHANISM mechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3410_512_KEY_PAIR_GEN);

            // Генерация ключевой пары
            rv = pkcs11.C_GenerateKeyPair(session, ref mechanism, pubKeyTemplate, Convert.ToUInt32(pubKeyTemplate.Length),
                privKeyTemplate, Convert.ToUInt32(privKeyTemplate.Length),
                ref pubKeyId, ref privKeyId);

            // In LowLevelAPI we have to free unmanaged memory taken by attributes
            for (int i = 0; i < privKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref privKeyTemplate[i].value);
                privKeyTemplate[i].valueLen = 0;
            }

            for (int i = 0; i < pubKeyTemplate.Length; i++)
            {
                UnmanagedMemory.Free(ref pubKeyTemplate[i].value);
                pubKeyTemplate[i].valueLen = 0;
            }

            return rv;
        }

        public static CKR DeriveKey(Pkcs11 pkcs11, uint session, uint pubKeyId, uint privKeyId, byte[] ukm, ref uint derivedKeyId)
        {
            CKR rv = CKR.CKR_OK;

            // Шаблон для создания ключа обмена
            CK_ATTRIBUTE[] derivedKeyTemplate = new CK_ATTRIBUTE[8];
            derivedKeyTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY);
            derivedKeyTemplate[1] = CkaUtils.CreateAttribute(CKA.CKA_LABEL, Settings.DerivedKeyLabel);
            derivedKeyTemplate[2] = CkaUtils.CreateAttribute(CKA.CKA_KEY_TYPE, (uint)Extended_CKK.CKK_GOST28147);
            derivedKeyTemplate[3] = CkaUtils.CreateAttribute(CKA.CKA_TOKEN, false);
            derivedKeyTemplate[4] = CkaUtils.CreateAttribute(CKA.CKA_MODIFIABLE, true);
            derivedKeyTemplate[5] = CkaUtils.CreateAttribute(CKA.CKA_PRIVATE, true);
            derivedKeyTemplate[6] = CkaUtils.CreateAttribute(CKA.CKA_EXTRACTABLE, true);
            derivedKeyTemplate[7] = CkaUtils.CreateAttribute(CKA.CKA_SENSITIVE, false);

            // Получаем публичный ключ по его Id
            CK_ATTRIBUTE[] valueTemplate = new CK_ATTRIBUTE[1];
            valueTemplate[0] = CkaUtils.CreateAttribute(CKA.CKA_VALUE);
            // In LowLevelAPI we have to allocate unmanaged memory for attribute value
            valueTemplate[0].value = UnmanagedMemory.Allocate(Convert.ToInt32(64));
            valueTemplate[0].valueLen = 64;

            // Get attribute value in second call
            rv = pkcs11.C_GetAttributeValue(session, pubKeyId, valueTemplate, Convert.ToUInt32(valueTemplate.Length));
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());
            byte[] publicKey = UnmanagedMemory.Read(valueTemplate[0].value, Convert.ToInt32(valueTemplate[0].valueLen));

            // Specify mechanism parameters
            // Note that we are allocating unmanaged memory that will have to be freed later
            CK_GOSTR3410_DERIVE_PARAMS deriveMechanismParams = new CK_GOSTR3410_DERIVE_PARAMS();
            deriveMechanismParams.Kdf = (uint)Extended_CKD.CKD_CPDIVERSIFY_KDF;

            deriveMechanismParams.PublicData = UnmanagedMemory.Allocate(publicKey.Length);
            UnmanagedMemory.Write(deriveMechanismParams.PublicData, publicKey);
            deriveMechanismParams.PublicDataLen = Convert.ToUInt32(publicKey.Length);
            deriveMechanismParams.UKM = UnmanagedMemory.Allocate(ukm.Length);
            UnmanagedMemory.Write(deriveMechanismParams.UKM, ukm);
            deriveMechanismParams.UKMLen = Convert.ToUInt32(ukm.Length);

            // Specify derivation mechanism with parameters
            // Note that CkmUtils.CreateMechanism() automaticaly copies mechanismParams into newly allocated unmanaged memory
            CK_MECHANISM deriveMechanism = CkmUtils.CreateMechanism((uint)Extended_CKM.CKM_GOSTR3410_DERIVE, deriveMechanismParams);

            // Derive key
            rv = pkcs11.C_DeriveKey(session, ref deriveMechanism, privKeyId, derivedKeyTemplate,
                Convert.ToUInt32(derivedKeyTemplate.Length), ref derivedKeyId);
            if (rv != CKR.CKR_OK)
                Assert.Fail(rv.ToString());

            // Do something interesting with derived key
            //Assert.IsTrue(derivedKeyId != CK.CK_INVALID_HANDLE);

            //// In LowLevelAPI we have to free all unmanaged memory we previously allocated
            //UnmanagedMemory.Free(ref mechanismParams.Data);
            //mechanismParams.Len = 0;

            //// In LowLevelAPI we have to free unmanaged memory taken by mechanism parameter
            //UnmanagedMemory.Free(ref mechanism.Parameter);
            //mechanism.ParameterLen = 0;

            return rv;
        }
    }
}
