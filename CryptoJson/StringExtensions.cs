using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Strings
{
    /// <summary>
    /// Class StringExtensions.
    /// </summary>
    public static class StringExtensions
    {

        public static StringBuilder AppendJoin<T>(this StringBuilder sb, char delimiter, IEnumerable<T> enumerable)
        {
            if (enumerable.Any())
            {
                sb.Append(enumerable.First());
                foreach (var o in enumerable.Skip(1))
                {
                    sb.AppendFormat("{0}{1}", delimiter, o);
                }
            }
            return sb;
        }

        /// <summary>
        /// Converts this string to it's secure equivalent
        /// </summary>
        /// <param name="unsecure">The input string</param>
        /// <returns>a secure string containing the characters from the unsecure string</returns>
        public static SecureString ToSecureString(this string unsecure)
        {
            SecureString secure = new SecureString();
            foreach (char c in unsecure) {
                secure.AppendChar(c);
            }

            return secure;
        }

        /// <summary>
        /// Converts this secure string to it's unsecure equivalent
        /// </summary>
        /// <param name="secure">The input secure string</param>
        /// <returns>an unsecure string, containing the characters from the secure string</returns>
        public static string ToUnSecureString(this SecureString secure) => 
            Marshal.PtrToStringUni(Marshal.SecureStringToGlobalAllocUnicode(secure));


        /// <summary>
        /// Converts objects to a delimited stringlist using "ToString()".
        /// </summary>
        /// <typeparam name="T">type of the objects</typeparam>
        /// <param name="objects">The objects</param>
        /// <param name="delimiter">The delimiter.</param>
        /// <returns>List of String</returns>
        public static String ToStringList<T>(this IEnumerable<T> objects, Char delimiter = ',') => 
            new StringBuilder().AppendJoin(delimiter, objects).ToString();

        /// <summary>
        /// Converts a delimited stringlist back to a List of string.
        /// </summary>
        /// <param name="stringList">The delimited string list.</param>
        /// <param name="delimiter">The delimiter</param>
        /// <returns>List&lt;String&gt;.</returns>
        public static List<String> ToList(this string stringList, Char delimiter = ',') => 
            stringList.Split(delimiter).ToList();

        /// <summary>
        /// Comverts a delimited stringlist back to its original form of a list
        /// </summary>
        /// <typeparam name="T">Type of the objects in the resulting list</typeparam>
        /// <param name="stringList">delimited list of strings</param>
        /// <param name="converterFunction">function to convert the resulting string into the object type</param>
        /// <param name="delimiter">delimiter</param>
        /// <returns>List of the objects</returns>
        public static List<T> ToList<T>(this string stringList, Func<string, T> converterFunction, Char delimiter = ',') => 
            stringList.Split(delimiter).Select(converterFunction).ToList();
        
    }
}
