namespace CryptStructure
{
    public class Constants
    {
        #region Описание флагов для CertFindCertificateInStore
        //public const int CERT_FIND_ANY = 0;
        public const int X509_ASN_ENCODING = 0x00000001;//Кодировку сообщений X.509
        public const int PKCS_7_ASN_ENCODING = 0x00010000;//Кодировку сообщений PKCS #7
        public const int PKCS_7_OR_X509_ASN_ENCODING = (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING);
        #endregion

        #region hash algorithm OIDs
        public const string szOID_OIWSEC_sha1 = "1.3.14.3.2.26";
        public const string szOID_NIST_sha256 = "2.16.840.1.101.3.4.2.1";
        public const string szOID_CP_GOST_R3411 = "1.2.643.2.2.9";
        public const string szOID_CP_GOST_R3411_12_256 = "1.2.643.7.1.1.2.2";
        public const string szOID_CP_GOST_R3410_12_512 = "1.2.643.7.1.1.1.2";
        #endregion

        #region crypt pubkey algorithm OIDs
        public const string szOID_CP_GOST_R3410EL = "1.2.643.2.2.19";
        public const string szOID_CP_GOST_R3410_12_256 = "1.2.643.7.1.1.1.1";
        public const string szOID_CP_GOST_R3411_12_512 = "1.2.643.7.1.1.2.3";
        #endregion

        #region dwFlags definitions for CryptAcquireContext
        /// <summary>
        /// Приложение запрашивает, чтобы поставщик служб CSP не отображал пользовательский интерфейс для этого контекста
        /// </summary>
        public const uint CRYPT_SILENT = 0x00000040;
        #endregion

        #region Определяет закрытый ключ для использования из контейнера ключей (CryptGetUserKey)
        /// <summary>
        /// ключ RSA, который можно использовать для подписывания и расшифровки
        /// </summary>
        public const int AT_KEYEXCHANGE = 1;
        /// <summary>
        /// только ключ подписи RSA
        /// </summary>
        public const int AT_SIGNATURE = 2;
        #endregion

        #region Тип выполняемого запроса на получение данных ключа (CryptGetKeyParam)
        /// <summary>
        /// Получение сертификата
        /// </summary>
        public const int KP_CERTIFICATE = 26;

        public const int KP_IV = 1;
        #endregion

        #region Указывает тип ключа BLOB для экспорта        
        public const byte SIMPLEBLOB = 0x1;
        public const byte PUBLICKEYBLOB = 0x6;
        /// <summary>
        /// Используется для передачи пар открытого и закрытого ключей.
        /// </summary>
        public const byte PRIVATEKEYBLOB = 0x7;
        public const byte PLAINTEXTKEYBLOB = 0x8;
        public const byte OPAQUEKEYBLOB = 0x9;
        public const byte PUBLICKEYBLOBEX = 0xA;
        public const byte SYMMETRICWRAPKEYBLOB = 0xB;
        #endregion

        #region тип подписи
        public const int CADES_DEFAULT = 0x00000000;
        public const int CADES_BES = 0x00000001;
        public const int CADES_T = 0x00000005;
        public const int CADES_X_LONG_TYPE_1 = 0x0000005D;
        public const int CADES_A = 0x000000DD;
        public const int PKCS7_TYPE = 0x0000ffff;
        #endregion

        #region Тип аутентификации
        public const int CADES_AUTH_ANONYMOUS = 0x00;
        public const int CADES_AUTH_BASIC = 0x01;
        public const int CADES_AUTH_NTLM = 0x02;
        public const int CADES_AUTH_DIGEST = 0x08;
        public const int CADES_AUTH_NEGOTIATE = 0x10;
        #endregion

        #region Тип извлекаемых данных метода CryptMsgGetParam
        public const uint CMSG_TYPE_PARAM = 1;
        /// <summary>
        /// Возвращает все сообщение PKCS #7 из сообщения, открытого для кодирования
        /// </summary>
        public const uint CMSG_CONTENT_PARAM = 2;
        public const uint CMSG_BARE_CONTENT_PARAM = 3;
        /// <summary>
        /// Возвращает тип содержимого (content-type)
        /// </summary>
        public const uint CMSG_INNER_CONTENT_TYPE_PARAM = 4;
        /// <summary>
        /// Возвращает число подписывателей полученного сообщения
        /// </summary>
        public const uint CMSG_SIGNER_COUNT_PARAM = 5;
        public const uint CMSG_SIGNER_INFO_PARAM = 6;
        public const uint CMSG_SIGNER_CERT_INFO_PARAM = 7;
        public const uint CMSG_SIGNER_HASH_ALGORITHM_PARAM = 8;
        public const uint CMSG_SIGNER_AUTH_ATTR_PARAM = 9;
        public const uint CMSG_SIGNER_UNAUTH_ATTR_PARAM = 10;
        public const uint CMSG_CERT_COUNT_PARAM = 11;
        public const uint CMSG_CERT_PARAM = 12;
        public const uint CMSG_CRL_COUNT_PARAM = 13;
        public const uint CMSG_CRL_PARAM = 14;
        public const uint CMSG_ENVELOPE_ALGORITHM_PARAM = 15;
        public const uint CMSG_RECIPIENT_COUNT_PARAM = 17;
        public const uint CMSG_RECIPIENT_INDEX_PARAM = 18;
        public const uint CMSG_RECIPIENT_INFO_PARAM = 19;
        public const uint CMSG_HASH_ALGORITHM_PARAM = 20;
        public const uint CMSG_HASH_DATA_PARAM = 21;
        public const uint CMSG_COMPUTED_HASH_PARAM = 22;
        public const uint CMSG_ENCRYPT_PARAM = 26;
        public const uint CMSG_ENCRYPTED_DIGEST = 27;
        public const uint CMSG_ENCODED_SIGNER = 28;
        public const uint CMSG_ENCODED_MESSAGE = 29;
        public const uint CMSG_VERSION_PARAM = 30;
        public const uint CMSG_ATTR_CERT_COUNT_PARAM = 31;
        public const uint CMSG_ATTR_CERT_PARAM = 32;
        public const uint CMSG_CMS_RECIPIENT_COUNT_PARAM = 33;
        public const uint CMSG_CMS_RECIPIENT_INDEX_PARAM = 34;
        public const uint CMSG_CMS_RECIPIENT_ENCRYPTED_KEY_INDEX_PARAM = 35;
        public const uint CMSG_CMS_RECIPIENT_INFO_PARAM = 36;
        public const uint CMSG_UNPROTECTED_ATTR_PARAM = 37;
        /// <summary>
        /// pvData data type: pointer to a BYTE array to receive a CERT_ID structure.
        /// Returns information on a message signer needed to identify the signer's public key. This could be a certificate's Issuer and SerialNumber, a KeyID, or a HashId. 
        /// To retrieve information for all the signers, call <see cref="CryptMsgGetParam"/> varying dwIndex from 0 to the number of signers minus one.
        /// </summary>
        public const uint CMSG_SIGNER_CERT_ID_PARAM = 38;
        public const uint CMSG_CMS_SIGNER_INFO_PARAM = 39;
        #endregion

        #region флаг поведения метода CryptMsgOpenToEncode и CadesMsgOpenToEncode
        public const int CMSG_DETACHED_FLAG = 0x00000004; // получение открепленной подписи
        public const int CPCMSG_CADES_DISABLE = 0x00000200; // Отключает добавление атрибутов.
        public const int CPCMSG_CADES_STRICT = 0x00000100; // Отключает добавление атрибутов.
        #endregion

        #region Тип сообщения
        public const uint CMSG_SIGNED = 2;
        #endregion

        public const uint CRYPT_ACQUIRE_CACHE_FLAG = 0x00000001;
        public const uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;
        public const uint CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004;
        public const uint CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000;
        public const uint CRYPT_ACQUIRE_ALLOW_NCRYPT_KEY_FLAG = 0x00010000;

        public const uint CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF;

        /// <summary>
        /// Specifies that the key exchange PIN is contained in pbData. The PIN is represented as a null-terminated ASCII string.
        /// </summary>
        public const uint PP_KEYEXCHANGE_PIN = 32;
        /// <summary>
        /// Specifies the signature PIN. The pbData parameter is a null-terminated ASCII string that represents the PIN.
        /// </summary>
        public const uint PP_SIGNATURE_PIN = 33;

        public const uint PP_SECURE_KEYEXCHANGE_PIN = 47;

        public const uint PP_SECURE_SIGNATURE_PIN = 48;

        #region MINIDUMP_TYPE
        public const int MiniDumpNormal = 0x00000000;
        #endregion

        /// <summary>
        /// pvSigner contains a pointer to a <see cref="CERT_CONTEXT"/> structure
        /// </summary>
        public const uint CMSG_VERIFY_SIGNER_CERT = 2;

        /// <summary>
        /// A <see cref="CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA"/> structure that specifies the signer index and public key to verify the message signature. 
        /// The signer public key can be a <see cref="CERT_PUBLIC_KEY_INFO"/> structure, a certificate context, or a certificate chain context.
        /// </summary>
        public const uint CMSG_CTRL_VERIFY_SIGNATURE_EX = 19;

        public const nint CERT_STORE_PROV_MSG = 1;

        /// <summary>
        /// Forces the freeing of memory for all contexts associated with the store. This flag can be safely used only when the store is opened in a function and neither the store handle nor any of its contexts are passed to any called functions
        /// </summary>
        public const uint CERT_CLOSE_STORE_FORCE_FLAG = 1;

        #region cert compare flags
        public const uint CERT_COMPARE_SHIFT = 16;
        public const uint CERT_COMPARE_CERT_ID = 16;
        #endregion

        #region cert find flags.
        /// <summary>
        /// Data type of pvFindPara: <see cref="CERT_ID"/> structure. 
        /// Find the certificate identified by the specified <see cref="CERT_ID"/>.
        /// </summary>
        public const uint CERT_FIND_CERT_ID = ((int)CERT_COMPARE_CERT_ID << (int)CERT_COMPARE_SHIFT);
        public const uint CERT_FIND_SUBJECT_STR = 0x00080007;
        #endregion

        #region Тип хранилища сертификата
        public const uint CERT_STORE_PROV_SYSTEM_A = 9;//Системное хранилище Linux
        public const uint CERT_STORE_PROV_SYSTEM_W = 10;// Системное хранилище Windows
        #endregion

        #region cert store location
        public const uint CERT_SYSTEM_STORE_CURRENT_USER_ID = 1;
        public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2;
        public const uint CERT_SYSTEM_STORE_LOCATION_SHIFT = 16;
        public const uint CERT_SYSTEM_STORE_LOCAL_MACHINE = ((int)CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
        public const uint CERT_SYSTEM_STORE_CURRENT_USER = ((int)CERT_SYSTEM_STORE_CURRENT_USER_ID << (int)CERT_SYSTEM_STORE_LOCATION_SHIFT);
        #endregion

        public const uint CERT_STORE_READONLY_FLAG = 0x00008000;
        public const uint CERT_STORE_OPEN_EXISTING_FLAG = 0x00004000;

        #region PKCS7 Content Types.
        public const string szOID_RSA_data = "1.2.840.113549.1.7.1";
        public const string szOID_RSA_signedData = "1.2.840.113549.1.7.2";
        public const string szOID_RSA_envelopedData = "1.2.840.113549.1.7.3";
        public const string szOID_RSA_signEnvData = "1.2.840.113549.1.7.4";
        public const string szOID_RSA_digestedData = "1.2.840.113549.1.7.5";
        public const string szOID_RSA_hashedData = "1.2.840.113549.1.7.5";
        public const string szOID_RSA_encryptedData = "1.2.840.113549.1.7.6";
        #endregion

        #region статус проверки подписи cades
        public const uint ADES_VERIFY_SUCCESS = 0x00;
        public const uint ADES_VERIFY_INVALID_REFS_AND_VALUES = 0x01;
        public const uint ADES_VERIFY_SIGNER_NOT_FOUND = 0x02;
        public const uint ADES_VERIFY_NO_VALID_SIGNATURE_TIMESTAMP = 0x03;
        public const uint ADES_VERIFY_REFS_AND_VALUES_NO_MATCH = 0x04;
        public const uint ADES_VERIFY_NO_CHAIN = 0x05;
        public const uint ADES_VERIFY_END_CERT_REVOCATION = 0x06;
        public const uint ADES_VERIFY_CHAIN_CERT_REVOCATION = 0x07;
        public const uint ADES_VERIFY_BAD_SIGNATURE = 0x08;
        public const uint ADES_VERIFY_NO_VALID_CADES_C_TIMESTAMP = 0x09;
        public const uint ADES_VERIFY_BAD_POLICY = 0x0A;
        public const uint ADES_VERIFY_UNSUPPORTED_ATTRIBUTE = 0x0B;
        public const uint ADES_VERIFY_FAILED_POLICY = 0x0C;
        public const uint ADES_VERIFY_ECONTENTTYPE_NO_MATCH = 0x0D;
        public const uint ADES_VERIFY_NO_VALID_ARCHIVE_TIMESTAMP = 0x0E;
        #endregion

        #region Типы, выполняемых операций CryptMsgControl
        public const uint CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR = 9;
        public const uint CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR = 8;

        #endregion

        #region Oid атрибутов
        public const string CertCRLTimestampAttributeOid = "1.2.840.113549.1.9.16.2.26";//штамп времени CAdES-C (на доказательства)
        public const string EscTimeStampAttributeOid = "1.2.840.113549.1.9.16.2.25";//штамп времени CAdES-C (на доказательства + подпись + штамп времени на подпись)
        public const string RevocationRefsAttibuteOid = "1.2.840.113549.1.9.16.2.22";//идентификаторы доказательств подлинности для сертификатов, идентификаторы которых хранятся в "completecertificate-references"
        public const string CertificateRefsAttibuteOid = "1.2.840.113549.1.9.16.2.21";
        public const string SignatureTimeStampAttibuteOid = "1.2.840.113549.1.9.16.2.14"; // signature-time-stamp  информация о доверенном времени(ответ от сервера TSP). Содержит tsp подпись значения самой подписи

        #endregion

        public const uint CERT_KEY_PROV_INFO_PROP_ID = 2;
        public const uint CERT_SHA1_HASH_PROP_ID = 3;
        public const uint CERT_KEY_CONTEXT_PROP_ID = 5;
        public const uint CERT_FRIENDLY_NAME_PROP_ID = 0x0000000B; // 11
        public const uint CERT_ARCHIVED_PROP_ID = 0x00000013; // 19
        public const uint CERT_KEY_IDENTIFIER_PROP_ID = 0x00000014; // 20
        public const uint CERT_PUBKEY_ALG_PARA_PROP_ID = 0x00000016; // 22
        public const uint CERT_NCRYPT_KEY_HANDLE_PROP_ID = 0x0000004E; // 78
        public const uint CERT_CLR_DELETE_KEY_PROP_ID = 0x0000007D; // 125

        public const uint CERT_COMPARE_NAME_STR_W = 8;
        //public const uint CERT_COMPARE_SHIFT = 16;
        public const uint CERT_INFO_SUBJECT_FLAG = 7;

        #region xades singnature verification dwStatus description
        public const int XADES_VERIFY_SUCCESS = 0x00;
        public const int XADES_VERIFY_INVALID_REFS_AND_VALUES = 0x01;
        public const int XADES_VERIFY_SIGNER_NOT_FOUND = 0x02;
        public const int XADES_VERIFY_NO_VALID_SIGNATURE_TIMESTAMP = 0x03;
        public const int XADES_VERIFY_REFS_AND_VALUES_NO_MATCH = 0x04;
        public const int XADES_VERIFY_NO_CHAIN = 0x05;
        public const int XADES_VERIFY_END_CERT_REVOCATION = 0x06;
        public const int XADES_VERIFY_CHAIN_CERT_REVOCATION = 0x07;
        public const int XADES_VERIFY_BAD_SIGNATURE = 0x08;
        public const int XADES_VERIFY_NO_VALID_SIG_AND_REFS_TIMESTAMP = 0x09;
        #endregion

        #region тип подписи XADES
        public const uint XML_XADES_SIGNATURE_TYPE_ENVELOPED = 0x00;
        public const uint XML_XADES_SIGNATURE_TYPE_ENVELOPING = 0x01;
        public const uint XML_XADES_SIGNATURE_TYPE_TEMPLATE = 0x02;
        #endregion

        #region формат подписи XADES
        public const uint XADES_BES = 0x00000020;
        public const uint XADES_T = 0x00000050;
        public const uint XADES_X_LONG_TYPE_1 = 0x000005d0;
        public const uint XADES_A = 0x000007d0;//пока не поддерживается в КриптоПро
        public const uint XADES_XMLDSIG = 0x00000000;
        public const uint XADES_NONE = 0xf0000000;
        #endregion

        #region Add certificate/CRL, encoded, context or element disposition values.
        public const uint CERT_STORE_ADD_NEW = 1;
        public const uint CERT_STORE_ADD_USE_EXISTING = 2;
        public const uint CERT_STORE_ADD_REPLACE_EXISTING = 3;
        public const uint CERT_STORE_ADD_ALWAYS = 4;
        public const uint CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5;
        public const uint CERT_STORE_ADD_NEWER = 6;
        public const uint CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7;
        #endregion

        #region параметры кодировки метода CryptEncodeObjectEx
        /// <summary>
        /// Вызываемая функция кодирования выделяет память для закодированных байтов. Указатель на выделенные байты возвращается в pvEncoded.
        /// </summary>
        public const uint CRYPT_ENCODE_ALLOC_FLAG = 32768;
        #endregion

        #region Типы передаваемой структуры в методе CryptEncodeObjectEx
        /// <summary>
        /// Указатель на CRYPT_ATTRIBUTE
        /// </summary>
        public const string PKCS_ATTRIBUTE = "22";
        #endregion
        public const int ALG_SID_G28147 = 30;
        public const int ALG_TYPE_BLOCK = (3 << 9);
        public const int ALG_CLASS_DATA_ENCRYPT = (3 << 13);
        public const int CALG_G28147 = (ALG_CLASS_DATA_ENCRYPT | ALG_TYPE_BLOCK | ALG_SID_G28147);

        public const int ALG_CLASS_HASH = (4 << 13);
        public const int ALG_TYPE_ANY = (0);
        public const int ALG_SID_GR3411_2012_256 = 33;
        public const int CALG_GR3411_2012_256 = (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_GR3411_2012_256);

        public const uint CRYPT_VERIFYCONTEXT = 0xF0000000;

        public const uint CRYPT_EXPORTABLE = 0x00000001;

        public const String szOID_CP_GOST_28147 = "1.2.643.2.2.21";
        public const String AuthorityKeyIdentifierOID = "2.5.29.35";
        public const String SubjectKeyIdentifierOID = "2.5.29.14";
        public const String CRLDistibutionPointOID = "2.5.29.31";
        public const String AuthorityInfoAccessOID = "1.3.6.1.5.5.7.1.1";
        public const String szOID_PRIVATEKEY_USAGE_PERIOD = "2.5.29.16";

        public const String szCPGUID_PRIVATEKEY_USAGE_PERIOD_Encode = "{E36FC6F5-4880-4CB7-BA51-1FCD92CA1453}";

        #region CryptGetProvParam
        public const uint PP_ENUMCONTAINERS = 2;
        #endregion

        public const uint CRYPT_FIRST = 1;
    }
}

