using Crypto.Entities;
using Crypto.Interfaces;
using Crypto.Pivot;
using System.Runtime.InteropServices;

namespace Crypto.Helpers
{
    public unsafe class PivotFunctionsHelper
    {
        public static byte[] GetBytesArrayFromBlob(CryptoProWrapper.Crypto.CRYPTOAPI_BLOB blob)
        {
            var len = blob.cbData;
            byte[] arr = new byte[len];
            Marshal.Copy((IntPtr)blob.pbData, arr, 0, len);
            Array.Reverse<byte>(arr);
            return arr;
        }

        public static DateTime ConvertFileTime(System.Runtime.InteropServices.ComTypes.FILETIME ft)
        {
            long time = ((long)ft.dwHighDateTime << 32) + ft.dwLowDateTime;
            var dto = DateTimeOffset.FromFileTime(time).ToLocalTime();
            return dto.DateTime;
        }

        public static string ToHexString(byte[] buffer)
        {
            return Convert.ToHexString(buffer);
        }

        public static ICStore PrepareStore()
        {
            var crlBytes = File.ReadAllBytes(@"certs/certcrl.crl");
            using var crl = new CRL(crlBytes);
            var memoryStore = new CStore();
            memoryStore.Open(StoreType.Memory);
            memoryStore.AddCRL(crl);
            return memoryStore;
        }

        public static bool CompareByteArrays(byte[] arr1, byte[] arr2)
        {
            if (arr1.Length != arr2.Length) return false;

            if (arr1.Length == 0) return true;

            for (int i = 0; i < arr1.Length; i++)
            {
                if (arr1[i] != arr2[i]) return false;
            }

            return true;
        }
    }
}
