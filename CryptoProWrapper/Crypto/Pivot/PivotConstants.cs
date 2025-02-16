namespace Crypto.Pivot
{
    public class PivotConstants
    {
        public const Int32 X509_ASN_ENCODING = 0x00000001;//Кодировку сообщений X.509
        public const Int32 PKCS_7_ASN_ENCODING = 0x00010000;//Кодировку сообщений PKCS #7
        public const Int32 PKCS_7_OR_X509_ASN_ENCODING = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;

        public const Int32 CADES_DEFAULT = 0x00000000;
        public const Int32 CADES_BES = 0x00000001;
        public const Int32 CADES_T = 0x00000005;
        public const Int32 CADES_X_LONG_TYPE_1 = 0x0000005D;
        public const Int32 CADES_A = 0x000000DD;
        public const Int32 PKCS7_TYPE = 0x0000ffff;

        // CertOpenStore
        // lpszStoreProvider
        public const Int32 CERT_STORE_PROV_MEMORY = 0x00000002;

        // CertOpenStore
        // dwFlags
        public const Int32 CERT_STORE_CREATE_NEW_FLAG = 0x00002000;

        // CertAddCertificateContextToStore
        // dwAddDisposition
        public const Int32 CERT_STORE_ADD_REPLACE_EXISTING = 3;

        public const int CERT_STORE_READONLY_FLAG = 0x00008000;
        public const int CERT_STORE_MAXIMUM_ALLOWED_FLAG = 0x00001000;
        public const int CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;
        public const int CERT_SYSTEM_STORE_CURRENT_USER_ID = 1;
        public const int CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2;
        public const int CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;
        public const int CERT_SYSTEM_STORE_CURRENT_USER = (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
        public const int CERT_SYSTEM_STORE_LOCAL_MACHINE = (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT);
    }
}
