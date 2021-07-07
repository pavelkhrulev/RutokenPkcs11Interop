using System;
using System.Runtime.InteropServices;
using Net.Pkcs11Interop.Common;

namespace Net.RutokenPkcs11Interop.Helpers
{
    public static class StringArrayHelpers
    {
        public static IntPtr[] ConvertStringArrayToIntPtrArray(string[] strings)
        {
            var intPtrArray = new IntPtr[strings.Length];
            for (var i = 0; i < strings.Length; i++)
            {
                PutNullTerminatedStringToIntPtr(strings[i], out intPtrArray[i]);
            }

            return intPtrArray;
        }

        public static void PutNullTerminatedStringToIntPtr(string str, out IntPtr ptr)
        {
            if (string.IsNullOrEmpty(str))
                throw new ArgumentNullException(str);

            // Переводим строку в байты
            var bytes = ConvertUtils.Utf8StringToBytes(str);
            // Выделяем на один байт больше,
            // который будет представлять собой терминальный ноль
            ptr = UnmanagedMemory.Allocate(bytes.Length + 1);
            // Копируем по адресу указателя
            Marshal.Copy(bytes, 0, ptr, bytes.Length);
        }

        public static void FreeUnmanagedIntPtrArray(IntPtr[] ptrArray)
        {
            for (var i = 0; i < ptrArray.Length; i++)
            {
                UnmanagedMemory.Free(ref ptrArray[i]);
            }
        }
    }
}
