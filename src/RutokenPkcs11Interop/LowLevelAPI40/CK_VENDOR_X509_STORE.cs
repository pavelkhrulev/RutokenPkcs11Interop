﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;
using Net.RutokenPkcs11Interop.HighLevelAPI;

using NativeULong = System.UInt32;

// Note: Code in this file is generated automatically

namespace Net.RutokenPkcs11Interop.LowLevelAPI40
{
    /// <summary>
    /// Структура, которая содержит указатели на необходимые для проверки подписи доверенные сертификаты,
    /// сертификаты подписывающей стороны и списки отозванных сертификатов
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 0, CharSet = CharSet.Unicode)]
    public struct CK_VENDOR_X509_STORE : IDisposable
    {
        public CK_VENDOR_X509_STORE(CkVendorX509Store store)
        {
            TrustedCertificates = new IntPtr();
            TrustedCertificateCount = 0;
            Certificates = new IntPtr();
            CertificateCount = 0;
            Crls = new IntPtr();
            CrlCount = 0;

            if (store.TrustedCertificates != null && store.TrustedCertificates.Any())
            {
                AllocateNativeCertificates(store.TrustedCertificates, ref TrustedCertificates,
                    ref TrustedCertificateCount);
            }

            if (store.Certificates != null && store.Certificates.Any())
            {
                AllocateNativeCertificates(store.Certificates, ref Certificates,
                    ref CertificateCount);
            }

            if (store.Crls != null && store.Crls.Any())
            {
                AllocateNativeCertificates(store.Crls, ref Crls,
                    ref CrlCount);
            }
        }

        /// <summary>
        /// Массив доверенных сертификатов
        /// </summary>
        public IntPtr TrustedCertificates;

        /// <summary>
        /// Количество доверенных сертификатов в массиве
        /// </summary>
        public NativeULong TrustedCertificateCount;

        /// <summary>
        /// Массив, содержащий сертификаты для проверки подписи
        /// </summary>
        public IntPtr Certificates;

        /// <summary>
        /// Количество сертификатов в цепочке сертификатов
        /// </summary>
        public NativeULong CertificateCount;

        /// <summary>
        /// Массив списков отзыва сертификатов
        /// </summary>
        public IntPtr Crls;

        /// <summary>
        /// Количество списков отзыва сертификатов в массиве
        /// </summary>
        public NativeULong CrlCount;

        private void AllocateNativeCertificates(IList<byte[]> managedCertificates, ref IntPtr certificatesPtr, ref NativeULong certificatesCount)
        {
            if (managedCertificates == null || !managedCertificates.Any())
                return;

            certificatesCount = (NativeULong)(managedCertificates.Count);

            var nativeCertificates = new CK_VENDOR_BUFFER[certificatesCount];

            for (NativeULong i = 0; i < certificatesCount; i++)
            {
                nativeCertificates[i].Data = UnmanagedMemory.Allocate(managedCertificates[ConvertUtils.UInt32ToInt32(i)].Length);
                UnmanagedMemory.Write(nativeCertificates[i].Data, managedCertificates[ConvertUtils.UInt32ToInt32(i)]);
                nativeCertificates[i].Size = (NativeULong)(managedCertificates[ConvertUtils.UInt32ToInt32(i)].Length);
            }

            var structSize = Marshal.SizeOf(typeof(CK_VENDOR_BUFFER));
            certificatesPtr = Marshal.AllocHGlobal(managedCertificates.Count * structSize);
            var ptr = certificatesPtr;
            for (NativeULong i = 0; i < certificatesCount; i++)
            {
                Marshal.StructureToPtr(nativeCertificates[i], ptr, false);
                ptr += structSize;
            }
        }

        public void Dispose()
        {
            if (TrustedCertificateCount != 0)
            {
                TrustedCertificateCount = 0;
                UnmanagedMemory.Free(ref TrustedCertificates);
            }

            if (CertificateCount != 0)
            {
                CertificateCount = 0;
                UnmanagedMemory.Free(ref Certificates);
            }

            if (CrlCount != 0)
            {
                CrlCount = 0;
                UnmanagedMemory.Free(ref Crls);
            }
        }
    }
}
