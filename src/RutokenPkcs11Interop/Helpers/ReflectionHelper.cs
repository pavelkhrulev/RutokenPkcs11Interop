using System;
using System.Reflection;

namespace Net.RutokenPkcs11Interop.Helpers
{
    /// <summary>
    /// Многие свойства в исходной библиотеке PKCSInterop имеют модификатор Internal.
    /// Поэтому их получение невозможно. Где-то можно было бы создавать новый объект,
    /// а где-то нет. Поэтому пока что для универсальности используем это класс,
    /// позволяющий получать скрытые свойства.
    /// </summary>
    internal static class ReflectionHelper
    {
        /// <summary>
        /// Returns a _private_ Property Value from a given Object. Uses Reflection.
        /// Throws a ArgumentOutOfRangeException if the Property is not found.
        /// </summary>
        /// <typeparam name="T">Type of the Property</typeparam>
        /// <param name="obj">Object from where the Property Value is returned</param>
        /// <param name="propName">Propertyname as string.</param>
        /// <returns>PropertyValue</returns>
        public static T GetPrivatePropertyValue<T>(this object obj, string propName)
        {
            if (obj == null) throw new ArgumentNullException(nameof(obj));
            PropertyInfo pi = obj.GetType().GetProperty(propName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
            if (pi == null) throw new ArgumentOutOfRangeException(nameof(propName),
                $"Property {propName} was not found in Type {obj.GetType().FullName}");

            return (T)pi.GetValue(obj, null);
        }

        /// <summary>
        /// Returns a private Property Value from a given Object. Uses Reflection.
        /// Throws a ArgumentOutOfRangeException if the Property is not found.
        /// </summary>
        /// <typeparam name="T">Type of the Property</typeparam>
        /// <param name="obj">Object from where the Property Value is returned</param>
        /// <param name="propName">Propertyname as string.</param>
        /// <returns>PropertyValue</returns>
        public static T GetPrivateFieldValue<T>(this object obj, string propName)
        {
            if (obj == null)
                throw new ArgumentNullException(nameof(obj));
            Type t = obj.GetType();
            FieldInfo fi = null;
            while (fi == null && t != null)
            {
                fi = t.GetField(propName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                t = t.BaseType;
            }
            if (fi == null)
                throw new ArgumentOutOfRangeException(nameof(propName),
                    $"Field {propName} was not found in Type {obj.GetType().FullName}");
            return (T)fi.GetValue(obj);
        }

        /// <summary>
        ///
        /// </summary>
        /// <param name="className"></param>
        /// <param name="methodName"></param>
        /// <param name="args"></param>
        /// <returns></returns>
        internal static object CallInternalStaticMethod(Type className, string methodName, params object[] args)
        {
            var method = className.GetMethod(methodName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Static);

            if (method == null)
                throw new NullReferenceException("Method not found");

            return method.Invoke(null, args);
        }

        /// <summary>
        /// Set a private Property Value on a given Object. Uses Reflection.
        /// </summary>
        /// <typeparam name="T">Type of the Property</typeparam>
        /// <param name="obj">Object from where the Property Value is returned</param>
        /// <param name="propName">Propertyname as string.</param>
        /// <param name="val">the value to set</param>
        /// <exception cref="ArgumentOutOfRangeException">if the Property is not found</exception>
        internal static void SetPrivateFieldValue<T>(this object obj, string propName, T val)
        {
            if (obj == null)
                throw new ArgumentNullException(nameof(obj));

            Type t = obj.GetType();
            FieldInfo fi = null;
            while (fi == null && t != null)
            {
                fi = t.GetField(propName, BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance);
                t = t.BaseType;
            }
            if (fi == null)
                throw new ArgumentOutOfRangeException(nameof(propName),
                    $"Field {propName} was not found in Type {obj.GetType().FullName}");
            fi.SetValue(obj, val);
        }
    }
}
