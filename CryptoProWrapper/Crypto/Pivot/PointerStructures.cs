using System.Runtime.InteropServices;

namespace CryptoProWrapper.Crypto
{
    public struct CERT_CONTEXT
    {
        public CertEncodingType dwCertEncodingType;
        public unsafe byte* pbCertEncoded;
        public int cbCertEncoded;
        public unsafe CERT_INFO* pCertInfo;
        public IntPtr hCertStore;
    }

    public struct CERT_INFO
    {
        public int dwVersion;
        public CRYPTOAPI_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPTOAPI_BLOB Issuer;
        public System.Runtime.InteropServices.ComTypes.FILETIME NotBefore; // FILETIME
        public System.Runtime.InteropServices.ComTypes.FILETIME NotAfter; // FILETIME
        public CRYPTOAPI_BLOB Subject;
        public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
        public CRYPT_BIT_BLOB IssuerUniqueId;
        public CRYPT_BIT_BLOB SubjectUniqueId;
        public int cExtension;
        public unsafe CERT_EXTENSION* rgExtension;
    }

    public struct CERT_EXTENSION
    {
        public IntPtr pszObjId;
        public int fCritical;
        public CRYPTOAPI_BLOB Value;
    }

    public struct CERT_PUBLIC_KEY_INFO
    {
        public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
        public CRYPT_BIT_BLOB PublicKey;
    }

    public struct CRYPT_BIT_BLOB
    {
        public int cbData;
        public unsafe byte* pbData;
        public int cUnusedBits;

        public unsafe byte[] ToByteArray()
        {
            if (cbData == 0)
                return Array.Empty<byte>();
            byte[] destination = new byte[cbData];
            Marshal.Copy((IntPtr)(void*)pbData, destination, 0, cbData);
            return destination;
        }
    }

    public struct CRYPT_ALGORITHM_IDENTIFIER
    {
        //[MarshalAs(UnmanagedType.LPStr)]
        //public string pszObjId;
        public nint pszObjId;
        public CRYPTOAPI_BLOB Parameters;
    }

    //public struct FILETIME
    //{
    //    private uint ftTimeLow;
    //    private uint ftTimeHigh;

    //    public DateTime ToDateTime() => DateTime.FromFileTime(((long)ftTimeHigh << 32) + ftTimeLow);

    //    public static FILETIME FromDateTime(DateTime dt)
    //    {
    //        long fileTime = dt.ToFileTime();
    //        return new FILETIME()
    //        {
    //            ftTimeLow = (uint)fileTime,
    //            ftTimeHigh = (uint)(fileTime >> 32)
    //        };
    //    }
    //}

    public struct CRYPTOAPI_BLOB
    {
        public int cbData;
        public unsafe byte* pbData;

        public unsafe CRYPTOAPI_BLOB(int cbData, byte* pbData)
        {
            this.cbData = cbData;
            this.pbData = pbData;
        }

        public unsafe byte[] ToByteArray()
        {
            if (cbData == 0)
                return Array.Empty<byte>();
            byte[] destination = new byte[cbData];
            Marshal.Copy((IntPtr)(void*)pbData, destination, 0, cbData);
            return destination;
        }
    }

    public enum CertEncodingType
    {
        X509_ASN_ENCODING = 1,
        PKCS_7_ASN_ENCODING = 65536, // 0x00010000
        All = 65537, // 0x00010001
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRL_CONTEXT
    {
        public int dwCertEncodingType;
        public IntPtr pbCrlEncoded;
        public int cbCrlEncoded;
        public unsafe CRL_INFO* pCrlInfo;
        public IntPtr hCertStore;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRL_INFO
    {
        public int dwVersion;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPTOAPI_BLOB Issuer;
        public System.Runtime.InteropServices.ComTypes.FILETIME ThisUpdate;
        public System.Runtime.InteropServices.ComTypes.FILETIME NextUpdate;
        public int cCRLEntry;
        public IntPtr rgCRLEntry;
        public int cExtension;
        public IntPtr rgExtension;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRL_ENTRY
    {
        public CRYPTOAPI_BLOB SerialNumber;
        public System.Runtime.InteropServices.ComTypes.FILETIME RevocationDate;
        public int cExtension;
        public IntPtr rgExtension;
    }
}
