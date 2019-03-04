using System;
using System.Runtime.InteropServices;

namespace RutokenPkcs11Interop.LowLevelAPI41
{
    /// <summary>
    /// Структура, которая содержит указатели на необходимые для проверки подписи доверенные сертификаты,
    /// сертификаты подписывающей стороны и списки отозванных сертификатов
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct CK_VENDOR_X509_STORE
    {
        /// <summary>
        /// Массив доверенных сертификатов
        /// </summary>
        public IntPtr TrustedCertificates;

        /// <summary>
        /// Количество доверенных сертификатов в массиве
        /// </summary>
        public uint TrustedCertificateCount;

        /// <summary>
        /// Массив, содержащий сертификаты для проверки подписи
        /// </summary>
        public IntPtr Certificates;

        /// <summary>
        /// Количество сертификатов в цепочке сертификатов
        /// </summary>
        public uint CertificateCount;

        /// <summary>
        /// Массив списков отзыва сертификатов
        /// </summary>
        public IntPtr Crls;

        /// <summary>
        /// Количество списков отзыва сертификатов в массиве
        /// </summary>
        public uint CrlCount;
    }
}
