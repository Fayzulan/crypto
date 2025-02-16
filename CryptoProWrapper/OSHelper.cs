using System.Security.Cryptography;
using System.Text;

namespace CryptoProWrapper
{
    public static class OSHelper
    {
        internal const string Kernel32 = "libcapi20.so";
        internal const string Crypt32 = "libcapi20.so";
        internal const String CADES = "libxades.so";
        internal const String ADVAPI32 = "libcapi20.so";
        internal const string OSPosfix = "A";
        internal const string Xades = "libxades.so";
        internal const string LinuxTSPClient = "libCryptoProTspClient.so";
        internal const String LibsPath = "Xades";

        //internal const string OSPosfix = "";
        //internal const String ADVAPI32 = "advapi32.dll";
        //internal const string Kernel32 = "kernel32.dll";
        //internal const string Crypt32 = "Crypt32.dll";
        //internal const String CADES = "cades.dll";
        //internal const String Xades = "xades.dll";
        //internal const string LinuxTSPClient = "libCryptoProTspClient.so";
        //internal const String LibsPath = "";

        /// <summary>
        /// Находимся в линуксе?
        /// </summary>
        public static bool fIsLinux
        {
            get
            {
                int iPlatform = (int)Environment.OSVersion.Platform;
                return (iPlatform == 4) || (iPlatform == 6) || (iPlatform == 128);
            }
        }

        public static int EncodingGetByteCount(string message)
        {
            if (fIsLinux)
            {
                return Encoding.UTF32.GetByteCount(message);
            }
            else
            {
                return Encoding.Unicode.GetByteCount(message);
            }
        }

        public static int EncodingGetBytes(ReadOnlySpan<char> chars, Span<byte> bytes)
        {
            if (fIsLinux)
            {
                return Encoding.UTF32.GetBytes(chars, bytes);
            }
            else
            {
                return Encoding.Unicode.GetBytes(chars, bytes);
            }
        }

        public static string EncodingGetString(byte[] bytes)
        {
            if (fIsLinux)
            {
                return Encoding.UTF32.GetString(bytes);
            }
            else
            {
                return Encoding.Unicode.GetString(bytes);
            }
        }

        public static string ComputeSHA1Hash(string rawData)
        {
            // Create a SHA1
            using (SHA1 sha256Hash = SHA1.Create())
            {
                // ComputeHash - returns byte array
                byte[] bytes = sha256Hash.ComputeHash(Encoding.UTF8.GetBytes(rawData));

                // Convert byte array to a string
                StringBuilder builder = new StringBuilder();
                for (int i = 0; i < bytes.Length; i++)
                {
                    builder.Append(bytes[i].ToString("x2"));
                }
                return builder.ToString();
            }
        }
    }
}
