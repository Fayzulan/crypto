using System.Runtime.InteropServices;

namespace CryptStructure
{
    public enum CrlAddDisposition : uint
    {
        CERT_STORE_ADD_NEW = 1,
        CERT_STORE_ADD_USE_EXISTING = 2,
        CERT_STORE_ADD_REPLACE_EXISTING = 3,
        CERT_STORE_ADD_ALWAYS = 4,
        CERT_STORE_ADD_REPLACE_EXISTING_INHERIT_PROPERTIES = 5,
        CERT_STORE_ADD_NEWER = 6,
        CERT_STORE_ADD_NEWER_INHERIT_PROPERTIES = 7,
    }

    //internal const uint CERT_CHAIN_REVOCATION_CHECK_CHAIN = 0x20000000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    unsafe public struct CPCERT_PRIVATEKEY_USAGE_PERIOD
    {
        public System.Runtime.InteropServices.ComTypes.FILETIME* pNotBefore;
        public System.Runtime.InteropServices.ComTypes.FILETIME* pNotAfter;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct FILETIME
    {
        public uint Low;
        public uint High;
        public static readonly FILETIME Zero = new FILETIME(0L);

        public FILETIME(long time)
        {
            unchecked
            {
                Low = (uint)time;
                High = (uint)(time >> 32);
            }
        }

        public long ToLong()
        {
            return ((long)High << 32) | Low;
        }
        public bool IsNull
        {
            get { return Low == 0 && High == 0; }
        }
    }

    [Flags]
    public enum CertRevocationCheckFlags
    {
        None = 0,
        EndCertificateOnly = 0x10000000,
        EntireChain = 0x20000000,
        ChainExcludeRoot = 0x40000000,
        IgnoreOfflineRevocation = unchecked((int)0x80000000),
        DisableRevocationCheck = unchecked((int)0x80000000)
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CertChainParameters
    {
        public int cbSize;
        public IntPtr RequestedUsage;
        public CertRevocationCheckFlags RevocationChecks;
        public IntPtr ExtraPolicyPara;
    }

    public struct CERT_CHAIN_POLICY_PARA
    {
        public int cbSize;
        public int dwFlags;
        public IntPtr pvExtraPolicyPara;
    }

    public struct CERT_CHAIN_POLICY_STATUS
    {
        public int cbSize;
        public int dwError;
        public IntPtr lChainIndex;
        public IntPtr lElementIndex;
        public IntPtr pvExtraPolicyStatus;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPTOAPI_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    /// <summary>
    /// Specifies an algorithm used to encrypt a private key. 
    /// The structure includes the object identifier (OID) of the algorithm and any needed parameters for that algorithm. 
    /// The parameters contained in its CRYPT_OBJID_BLOB are encoded.
    /// </summary>
    /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_algorithm_identifier</remarks>
    //[StructLayout(LayoutKind.Sequential)]
    //public struct CRYPT_ALGORITHM_IDENTIFIER
    //{
    //    /// <summary>
    //    /// An OID of an algorithm (LPSTR)
    //    /// </summary>
    //    // [MarshalAs(UnmanagedType.LPStr)]
    //    public nint pszObjId;

    //    /// <summary>
    //    /// A BLOB that provides encoded algorithm-specific parameters. In many cases, there are no parameters. This is indicated by setting the cbData member of the Parameters BLOB to zero.
    //    /// </summary>
    //    public CRYPT_INTEGER_BLOB Parameters;
    //}

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_SIGN_MESSAGE_PARA
    {
        public uint cbSize;
        public uint dwMsgEncodingType;
        public nint pSigningCert;
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        public nint pvHashAuxInfo;
        public uint cMsgCert;
        public nint rgpMsgCert;
        public uint cMsgCrl;
        public nint rgpMsgCrl;
        public uint cAuthAttr;
        public nint rgAuthAttr;
        public uint cUnauthAttr;
        public nint rgUnauthAttr;
        public uint dwFlags;
        public uint dwInnerContentType;
        public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
        public nint pvHashEncryptionAuxInfo;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CADES_SIGN_MESSAGE_PARA
    {
        public uint dwSize;
        public nint pSignMessagePara;
        public nint pCadesSignPara;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct PCRYPT_DATA_BLOB
    {
        public uint cbData;
        public nint pbData;
    }

    /// <summary>
    /// Структура, содержащая параметры создания усовершенствованной подписи
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CADES_SIGN_PARA
    {
        /// <summary>
        /// Размер структуры в байтах.
        /// </summary>
        public uint dwSize;

        /// <summary>
        /// Тип усовершенствованной подписи (см. примечания). По умолчанию используется тип подписи CADES_DEFAULT.
        /// </summary>
        public uint dwCadesType;

        /// <summary>
        /// Указатель на контекст сертификата используемого для создания подписи (может быть равен NULL)
        /// </summary>
        public nint pSignerCert;

        /// <summary>
        /// Алгоритм хэширования для создания идентификаторов (может быть равен NULL)
        /// </summary>
        public nint szHashAlgorithm;

        /// <summary>
        /// Хранилище, содержащее дополнительные сертификаты и CRL для сбора доказательств действительности сертификата подписи (может быть равно NULL).
        /// </summary>
        public nint hAdditionalStore;

        /// <summary>
        /// Указатель на структуру CADES_SERVICE_CONNECTION_PARA с параметрами соединения со службой штампов времени (может быть равным NULL)
        /// </summary>
        //public CADES_SERVICE_CONNECTION_PARA pTspConnectionPara;
        public nint pTspConnectionPara;

        /// <summary>
        /// Указатель на структуру CADES_PROXY_PARA с параметрами прокси (может быть равным NULL).
        /// </summary>
        public nint pProxyPara;

        /// <summary>
        /// Указатель на VOID для передачи параметров подписи (доступен, начиная с версии SDK 2.00.12098. Может быть равным NULL).
        /// </summary>
        public nint pCadesExtraPara;

        /// <summary>
        /// Количество адресов служб OCSP в параметре rgAdditionalOCSPServices (доступен, начиная с версии SDK 2.00.13126. Может быть равным 0).
        /// </summary>
        public uint cAdditionalOCSPServices;

        /// <summary>
        /// Дополнительные адреса OCSP служб для получения статуса сертификата подписанта. (доступен, начиная с версии SDK 2.00.13126. Может быть равным NULL).
        /// </summary>
        //[MarshalAs(UnmanagedType.LPStr)]
        //public string rgAdditionalOCSPServices;
        //[MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.LPStr, SizeConst = 100)]
        public nint rgAdditionalOCSPServices;
    }

    /// <summary>
    /// Структура, содержащая параметры соединения со службой
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CADES_SERVICE_CONNECTION_PARA
    {
        /// <summary>
        /// Размер структуры в байтах.
        /// </summary>
        public uint dwSize;

        /// <summary>
        /// Адрес веб-сервиса (LPCWSTR)
        /// </summary>
        //[MarshalAs(UnmanagedType.LPStr)]
        //public string wszUri;
        public nint wszUri;

        /// <summary>
        /// Указатель на структуру CADES_AUTH_PARA с параметрами аутентификации для доступа к службе
        /// </summary>
        public nint pAuthPara;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CADES_AUTH_PARA
    {
        /// <summary>
        ///  dwSize Размер структуры в байтах.
        /// </summary>
        public uint dwSize;

        /// <summary>
        /// Тип аутентификации(cм.примечания).
        /// </summary>
        public uint dwAuthType;

        /// <summary>
        /// Имя пользователя(опциональный параметр, используется в зависимости от применяемой схемы аутентификации).
        /// </summary>
        public string wszUsername;

        /// <summary>
        /// Пароль(опциональный параметр, используется в зависимости от применяемой схемы аутентификации).
        /// </summary>
        public string wszPassword;

        /// <summary>
        /// Клиентский сертификат(опциональный параметр, используется в зависимости от применяемой схемы аутентификации).
        /// </summary>
        public IntPtr pClientCertificate;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct BLOB
    {
        public int cbData;
        public IntPtr pbData;

        public void Dispose()
        {
            if (!pbData.Equals(IntPtr.Zero)) { Marshal.FreeHGlobal(pbData); }
        }
    }



    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_ID
    {
        public int dwIdChoice;
        public BLOB IssuerSerialNumberOrKeyIdOrHashId;
    }

    /// <summary>
    /// Contains signer information.
    /// </summary>
    /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signer_encode_info</remarks>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CMSG_SIGNER_ENCODE_INFO
    {
        /// <summary>
        /// The size, in bytes, of this structure
        /// </summary>
        public uint cbSize;

        /// <summary>
        /// A pointer to a <see cref="CERT_INFO"/> structure that contains the Issuer, SerialNumber, and SubjectPublicKeyInfo members
        /// </summary>
        public nint pCertInfo;

        /// <summary>
        /// A handle to the CSP Key or to the CNG NCryptKey or to the CNG BCryptKey
        /// </summary>
        public nint hCryptProv;

        /// <summary>
        /// Specifies the private key to be used
        /// </summary>
        public uint dwKeySpec;

        /// <summary>
        /// A <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure that specifies the hash algorithm
        /// </summary>
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        //public nint HashAlgorithm;

        /// <summary>
        /// Not used. This member must be set to NULL.
        /// </summary>
        public nint pvHashAuxInfo;

        /// <summary>
        /// The number of elements in the rgAuthAttr array. If no authenticated attributes are present in rgAuthAttr, then cAuthAttr is zero
        /// </summary>
        public uint cAuthAttr;

        /// <summary>
        /// An array of pointers to <see cref="CRYPT_ATTRIBUTE"/> structures, each of which contains authenticated attribute information
        /// </summary>
        public nint rgAuthAttr;

        /// <summary>
        /// The number of elements in the rgUnauthAttr array. If there are no unauthenticated attributes, cUnauthAttr is zero
        /// </summary>
        public uint cUnauthAttr;

        /// <summary>
        /// An array of pointers to <see cref="CRYPT_ATTRIBUTE"/> structures, each of which contains unauthenticated attribute information
        /// </summary>
        public nint rgUnauthAttr;

        /// <summary>
        /// A <see cref="CERT_ID"/> structure that contains a unique identifier of the signer's certificate
        /// </summary>
        public CERT_ID SignerId;
        //public nint SignerId;

        /// <summary>
        /// A <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure optionally used with PKCS #7 with CMS. If this member is not NULL, the algorithm identified is used instead of the SubjectPublicKeyInfo.Algorithm algorithm. 
        /// If this member is set to szOID_PKIX_NO_SIGNATURE, the signature value contains only the hash octets
        /// </summary>
        public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;
        //public nint HashEncryptionAlgorithm;

        /// <summary>
        /// This member is not used. This member must be set to NULL if it is present in the data structure
        /// </summary>
        public nint pvHashEncryptionAuxInfo;
    }

    /// <summary>
    /// Contains information to be passed to <see cref="CryptMsgOpenToEncode"/> if dwMsgType is CMSG_SIGNED
    /// </summary>
    /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signed_encode_info</remarks>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CMSG_SIGNED_ENCODE_INFO
    {
        /// <summary>
        /// Size of this structure in bytes
        /// </summary>
        public uint cbSize;

        /// <summary>
        /// Number of elements in the rgSigners array
        /// </summary>
        public uint cSigners;

        /// <summary>
        /// Array of pointers to <see cref="CMSG_SIGNER_ENCODE_INFO"/> structures each holding signer information
        /// </summary>
        public nint rgSigners;

        /// <summary>
        /// Number of elements in the rgCertEncoded array
        /// </summary>
        public uint cCertEncoded;

        /// <summary>
        /// Array of pointers to <see cref="CRYPT_INTEGER_BLOB"/> structures, each containing an encoded certificate
        /// </summary>
        public nint rgCertEncoded;

        /// <summary>
        /// Number of elements in the rgCrlEncoded array
        /// </summary>
        public uint cCrlEncoded;

        /// <summary>
        /// Array of pointers to <see cref="CRYPT_INTEGER_BLOB"/> structures, each containing an encoded CRL
        /// </summary>
        public nint rgCrlEncoded;

        /// <summary>
        /// Number of elements in the rgAttrCertEncoded array. Used only if CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS is defined
        /// </summary>
        public uint cAttrCertEncoded;

        /// <summary>
        /// Array of encoded attribute certificates. Used only if CMSG_SIGNED_ENCODE_INFO_HAS_CMS_FIELDS is defined. This array of encoded attribute certificates can be used with CMS for PKCS #7 processing
        /// </summary>
        public nint rgAttrCertEncoded;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CADES_ENCODE_INFO
    {
        public uint dwSize;
        public nint pSignedEncodeInfo;
        public uint cSignerCerts;
        public nint rgSignerCerts;
        public uint cHashAlgorithms;
        public nint rgHashAlgorithms;
    }

    internal delegate bool PFN_CMSG_STREAM_OUTPUT(IntPtr pvArg, IntPtr pbData, uint cbData, bool fFinal);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public class CMSG_STREAM_INFO
    {
        internal CMSG_STREAM_INFO(uint cbContent, PFN_CMSG_STREAM_OUTPUT pfnStreamOutput, IntPtr pvArg)
        {
            this.cbContent = cbContent;
            this.pfnStreamOutput = pfnStreamOutput;
            this.pvArg = pvArg;
        }

        internal uint cbContent;
        internal PFN_CMSG_STREAM_OUTPUT pfnStreamOutput;
        internal IntPtr pvArg;
    }

    /// <summary>
    /// This CryptoAPI structure is used for an arbitrary array of bytes. It is declared in Wincrypt.h and provides flexibility for objects that can contain various data types.
    /// </summary>
    /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_integer_blob</remarks>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_INTEGER_BLOB
    {
        /// <summary>
        /// The count of bytes in the buffer pointed to by pbData
        /// </summary>
        public uint cbData;

        /// <summary>
        /// A pointer to a block of data bytes
        /// </summary>
        public nint pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_ATTR_BLOB
    {
        /// DWORD->unsigned int
        public uint cbData;

        /// BYTE*
        public nint pbData;
    }

    /// <summary>
    /// Contains both the encoded and decoded representations of a certificate
    /// </summary>
    /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cert_context</remarks>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CERT_CONTEXT
    {
        /// <summary>
        /// Type of encoding used
        /// </summary>
        public uint dwCertEncodingType;

        /// <summary>
        /// A pointer to a buffer that contains the encoded certificate
        /// </summary>
        public nint pbCertEncoded;

        /// <summary>
        /// The size, in bytes, of the encoded certificate
        /// </summary>
        public uint cbCertEncoded;

        /// <summary>
        /// The address of a <see cref="CERT_INFO"/> structure that contains the certificate information
        /// </summary>
        public nint pCertInfo;

        /// <summary>
        /// A handle to the certificate store that contains the certificate context
        /// </summary>
        public nint hCertStore;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    public struct MINIDUMP_EXCEPTION_INFORMATION
    {
        public uint ThreadId;
        public IntPtr ExceptionPointers;
        public int ClientPointers;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct FILETIME2
    {
        uint dwLowDateTime;
        uint dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_DATA_BLOB
    {
        public Int32 cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CADES_VERIFICATION_INFO
    {
        public uint dwSize;
        public uint dwStatus;
        public IntPtr pSignerCert;
        public /*FILETIME*/IntPtr pSigningTime;
        public /*FILETIME*/IntPtr pReserved;
        public /*FILETIME*/IntPtr pSignatureTimeStampTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CADES_VERIFY_MESSAGE_PARA
    {
        public uint dwSize;
        public nint/*CRYPT_VERIFY_MESSAGE_PARA*/ pVerifyMessagePara;
        public nint/*CADES_VERIFICATION_PARA*/ pCadesVerifyPara;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_VERIFY_MESSAGE_PARA
    {
        public uint cbSize;
        public uint dwMsgAndCertEncodingType;
        public uint hCryptProv;
        public nint pfnGetSignerCertificate;
        public nint pvGetArg;
        public nint pStrongSignPara;
    }

    /// <summary>
    /// Структура, содержащая дополнительные параметры проверки усовершенствованной подписи
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CADES_VERIFICATION_PARA
    {
        /// <summary>
        /// Размер структуры в байтах
        /// </summary>
        public uint dwSize;

        /// <summary>
        /// Не используется.
        /// </summary>
        public IntPtr pMessageContentHash;

        /// <summary>
        /// Данный параметр задаёт настройки прокси для доступа к службам актуальных статусов в процессе проверки усовершенствованной подписи. 
        /// Если указатель равен NULL, то для доступа к службам будут использоваться соответствующие настройки групповой политики клиента (OCSP Client)
        /// </summary>
        public /*CADES_PROXY_PARA*/IntPtr pProxyPara;

        /// <summary>
        /// Дополнительное хранилище сертификатов для поиска (может быть равным NULL). 
        /// Если проверяется подпись CAdES BES, то сертификаты, необходимые для проверки подписи, ищутся в хранилищах текущего пользователя "My" (Личные), 
        /// "Addressbook" (Другие пользователи), "CA" (Промежуточные центры сертификации) и "Root" (Доверенные корневые центры сертификации). 
        /// Если поле hStore заполнено, то поиск сертификатов и списков отзыва сертификатов осуществляется дополнительно в этом хранилище. 
        /// При проверке подписи CAdES-X Long Type 1 данное поле используется только для проверки внешнего штампа, 
        /// т.к. все необходимые данные для проверки внутреннего штампа содержатся в атрибутах подписи.
        /// </summary>
        public IntPtr hStore;

        /// <summary>
        /// Зарезервирован для будущего использования. Должен быть равен FALSE.
        /// </summary>
        public bool bReserved2;

        /// <summary>
        /// Зарезервирован для будущего использования. Должен быть равен NULL.
        /// </summary>
        public IntPtr pReserved3;

        /// <summary>
        /// Тип подписи, соответствие которому необходимо проверить
        /// </summary>
        public uint dwCadesType;

        /// <summary>
        /// Дополнительные параметры проверки подписи. Возможные значения флагов: CADES_SKIP_IE_PROXY_CONFIGURATION = 0x00000004 Пропустить запрос настроек прокси-сервера у IE
        /// </summary>
        public uint dwFlags;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CADES_PROXY_PARA
    {
        public uint dwSize;
        public nint wszProxyUri;
        //public CADES_AUTH_PARA pProxyAuthPara;
        public nint pProxyAuthPara;
    }

    //[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    //public struct CERT_CONTEXT
    //{
    //    public uint dwCertEncodingType;
    //    public IntPtr pbCertEncoded;
    //    public uint cbCertEncoded;
    //    public IntPtr pCertInfo;
    //    public IntPtr hCertStore;
    //}

    //[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    //public struct CADES_AUTH_PARA
    //{
    //    public uint dwSize;
    //    public uint dwAuthType;
    //    public string wszUsername;
    //    public string wszPassword;
    //    public /*CERT_CONTEXT*/IntPtr pClientCertificate;
    //}

    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_OBJID_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PCADES_VIEW_SIGNATURE_PARA
    {
        public uint dwSize;
        public uint dwMsgEncodingType;
        public nint hCryptProv;
    }

    /// <summary>
	/// Contains information used to verify a message signature. It contains the signer index and signer public key. The signer public key can be the signer's <see cref="CERT_PUBLIC_KEY_INFO"/> structure, certificate context, or chain context.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_ctrl_verify_signature_ex_para</remarks>
	[StructLayout(LayoutKind.Sequential)]
    public struct CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA
    {
        /// <summary>
        /// The size, in bytes, of this structure. 
        /// </summary>
        public uint cbSize;

        /// <summary>
        /// This member is not used and should be set to NULL.
        /// </summary>
        public nint hCryptProv;

        /// <summary>
        /// The index of the signer in the message.
        /// </summary>
        public uint dwSignerIndex;

        /// <summary>
        /// The structure that contains the signer information.
        /// </summary>
        public uint dwSignerType;

        /// <summary>
        /// A pointer to a <see cref="CERT_PUBLIC_KEY_INFO"/> structure, a certificate context, a chain context, or NULL depending on the value of dwSignerType.
        /// </summary>
        public nint pvSigner;
    }

    /// <summary>
    /// Структура с дополнительной информацией о проверке подписи
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct PCADES_VERIFICATION_INFO
    {
        public uint dwSize;

        /// <summary>
        /// Статус проверки сообщения
        /// </summary>
        public uint dwStatus;

        /// <summary>
        /// Найденный в процессе проверки контекст сертификата, на ключе которого была сделана подпись.
        /// </summary>
        public nint pSignerCert;

        /// <summary>
        /// Найденное в процессе проверки время в атрибуте SigningTime.
        /// </summary>
        public DateTime pSigningTime;

        public DateTime pReserved;

        /// <summary>
        /// Найденное в процессе проверки время в штампе времени на подпись.
        /// </summary>
        public DateTime pSignatureTimeStampTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CADES_COSIGN_PARA
    {
        public uint dwSize;

        public nint pSigner;

        public nint pCadesSignPara;
    }

    /// <summary>
	/// Specifies an attribute that has one or more values
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_attribute</remarks>
	[StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_ATTRIBUTE
    {
        /// <summary>
        /// An object identifier (OID) that specifies the type of data contained in the rgValue array
        /// </summary>
        [MarshalAs(UnmanagedType.LPStr)]
        public string pszObjId;

        /// <summary>
        /// A DWORD value that indicates the number of elements in the rgValue array
        /// </summary>
        public uint cValue;

        /// <summary>
        /// Pointer to an array of <see cref="CRYPT_INTEGER_BLOB"/> structures
        /// </summary>
        public nint rgValue;

    }

    /// <summary>
	/// Contains an array of attributes
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-crypt_attributes</remarks>
	[StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_ATTRIBUTES
    {
        /// <summary>
        /// Number of elements in the rgAttr array
        /// </summary>
        public uint cAttr;

        /// <summary>
        /// Array of <see cref="CRYPT_ATTRIBUTE"/> structures
        /// </summary>
        public nint rgAttr;

    }

    /// <summary>
	/// Contains the content of the PKCS #7 defined SignerInfo in signed messages. In decoding a received message, <see cref="CryptMsgGetParam"/> is called for each signer to get a <see cref="CMSG_SIGNER_INFO"/> structure.
	/// </summary>
	/// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/ns-wincrypt-cmsg_signer_info</remarks>
	[StructLayout(LayoutKind.Sequential)]
    public struct CMSG_SIGNER_INFO
    {
        /// <summary>
        /// The version of this structure.
        /// </summary>
        public uint dwVersion;

        /// <summary>
        /// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the issuer of a certificate with the public key needed to verify a signature.
        /// </summary>
        public CRYPT_INTEGER_BLOB Issuer;

        /// <summary>
        /// A <see cref="CRYPT_INTEGER_BLOB"/> structure that contains the serial number of the certificate that contains the public key needed to verify a signature.
        /// </summary>
        public CRYPT_INTEGER_BLOB SerialNumber;

        /// <summary>
        /// <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure specifying the algorithm used in generating the hash of a message.
        /// </summary>
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;

        /// <summary>
        /// <see cref="CRYPT_ALGORITHM_IDENTIFIER"/> structure specifying the algorithm used to encrypt the hash.
        /// </summary>
        public CRYPT_ALGORITHM_IDENTIFIER HashEncryptionAlgorithm;

        /// <summary>
        /// A <see cref="CRYPT_DATA_BLOB"/> that contains the encrypted hash of the message, the signature.
        /// </summary>
        public CRYPT_INTEGER_BLOB EncryptedHash;

        /// <summary>
        /// <see cref="CRYPT_ATTRIBUTES"/> structure containing authenticated attributes of the signer.
        /// </summary>
        public CRYPT_ATTRIBUTES AuthAttrs;

        /// <summary>
        /// <see cref="CRYPT_ATTRIBUTES"/> structure containing unauthenticated attributes of the signer.
        /// </summary>
        public CRYPT_ATTRIBUTES UnauthAttrs;
    }

    /// <summary>
    /// Используется для удаления атрибута подписателя подписанного сообщения без проверки подлинности
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA
    {
        /// <summary>
        /// Размер этой структуры в байтах
        /// </summary>
        public uint cbSize;

        /// <summary>
        /// Индекс подписывающего в массиве rgSigners
        /// </summary>
        public uint dwSignerIndex;

        /// <summary>
        /// Индекс атрибута в массиве rgUnauthAttr
        /// </summary>
        public uint dwUnauthAttrIndex;
    }

    /// <summary>
    /// Используется для добавления атрибута без проверки подлинности для подписываемого сообщения
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA
    {
        /// <summary>
        /// Размер этой структуры в байтах
        /// </summary>
        public uint cbSize;

        /// <summary>
        /// Индекс подписывающего в массиве rgSigners
        /// </summary>
        public uint dwSignerIndex;

        /// <summary>
        /// Данные нового атрибута
        /// </summary>
        public CRYPT_DATA_BLOB blob;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_KEY_PROV_INFO
    {
        public unsafe char* pwszContainerName;
        public unsafe char* pwszProvName;
        public int dwProvType;
        public int dwFlags;
        public int cProvParam;
        public IntPtr rgProvParam;
        public int dwKeySpec;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct XADES_VERIFICATION_INFO
    {
        public uint dwSize;
        public uint dwStatus;
        public uint dwVerifiedXadesType;
        public IntPtr pSignerCert; // CERT_CONTEXT
        public IntPtr pSigningTime; // LPFILETIME
        public IntPtr pReserved; // LPFILETIME
        public IntPtr pSignatureTimeStampTime; // LPFILETIME
        public IntPtr pSigAndRefsTimeStampTime; // LPFILETIME
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct XADES_VERIFICATION_INFO_ARRAY
    {
        public uint dwSize;
        public uint cbCount;
        public IntPtr pXadesVerificationInfo; // XADES_VERIFICATION_INFO
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct XADES_VERIFY_MESSAGE_PARA
    {
        public uint dwSize;
        public nint pXadesVerifyPara; // XADES_VERIFICATION_PARA
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct XADES_VERIFICATION_PARA
    {
        public uint dwSize;
        public IntPtr pProxyPara; // CADES_PROXY_PARA
        public IntPtr hStore; // HCERTSTORE
        public bool bIsDetached;
        public IntPtr pReserved3; // LPVOID
        public uint dwSignatureType;
        public uint dwFlags;
    }

    /// <summary>
    /// Структура, содержащая параметры создания усовершенствованной XAdES подписи
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct XADES_SIGN_PARA
    {
        /// <summary>
        /// Размер структуры в байтах.
        /// </summary>
        public uint dwSize;

        /// <summary>
        /// Тип усовершенствованной XAdES подписи
        /// </summary>
        public uint dwSignatureType;

        /// <summary>
        /// Указатель на контекст сертификата (PCCERT_CONTEXT) используемого для создания XAdES подписи
        /// </summary>
        public nint pSignerCert;

        /// <summary>
        /// URI или URN алгоритма хэширования (может быть равен NULL). Данный алгоритм используется для хэширования данных, сертификатов, CRL и OCSP ответов 
        /// при создании ссылок на доказательства, использованные при проверке сертификата, на ключе которого была сделана подпись. 
        /// Если этот параметр равен NULL, то алгоритм хэширования определяется по алгоритму ключа подписи
        /// </summary>
        public nint szDigestMethod;

        /// <summary>
        /// URI или URN алгоритма подписи (может быть равен NULL). Данный алгоритм используется для подписи данных. 
        /// Если этот параметр равен NULL, то алгоритм подписи определяется по алгоритму ключа подписи
        /// </summary>
        public nint szSignatureMethod;

        /// <summary>
        /// Хранилище (HCERTSTORE), содержащее дополнительные сертификаты и CRL для сбора доказательств действительности сертификата подписи
        /// </summary>
        public nint hAdditionalStore;

        /// <summary>
        /// Указатель на структуру CADES_SERVICE_CONNECTION_PARA с параметрами соединения со службой штампов времени (может быть равным NULL). 
        /// Если указатель равен NULL, то используются настройки групповой политики для CryptoPro TSP Client
        /// </summary>
        public nint pTspConnectionPara;

        /// <summary>
        /// Указатель на структуру CADES_PROXY_PARA с параметрами прокси (может быть равным NULL). 
        /// Данный параметр задаёт настройки прокси для доступа к службам актуальных статусов и к службе штампов времени в процессе создания усовершенствованной подписи.
        /// </summary>
        public nint pProxyPara;

        /// <summary>
        /// Указатель на VOID для передачи параметров XAdES подписи. Может быть равным NULL
        /// </summary>
        public nint pXadesExtraPara;

        /// <summary>
        /// Количество адресов служб OCSP в параметре rgAdditionalOCSPServices
        /// </summary>
        public uint cAdditionalOCSPServices;

        /// <summary>
        /// Дополнительные адреса (LPCWSTR*) OCSP служб для получения статуса сертификата подписанта
        /// </summary>
        public nint rgAdditionalOCSPServices;
    }

    /// <summary>
    /// Структура, задаваемая в качестве параметра функции XadesSign
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct XADES_SIGN_MESSAGE_PARA
    {
        /// <summary>
        /// Размер структуры в байтах
        /// </summary>
        public uint dwSize;

        /// <summary>
        /// Указатель на структуру XADES_SIGN_PARA
        /// </summary>
        public nint pXadesSignPara;
    }

    /// <summary>
    /// Структура, для добавления подписываемых данных в tsp
    /// </summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct TO_TIME_STAMP
    {
        //public sbyte[] text;
        public nint text;

        public uint textLength;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_ENCRYPT_MESSAGE_PARA
    {
        public uint cbSize;
        public uint dwMsgEncodingType;
        public IntPtr hCryptProv;
        public CRYPT_ALGORITHM_IDENTIFIER ContentEncryptionAlgorithm;
        IntPtr pvEncryptionAuxInfo;
        public uint dwFlags;
        public uint dwInnerContentType;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_ALGORITHM_IDENTIFIER
    {
        //[MarshalAs(UnmanagedType.LPStr)]
        public nint pszObjId;
        public CRYPTOAPI_BLOB Parameters;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct CRYPT_DECRYPT_MESSAGE_PARA
    {
        public uint cbSize;
        public uint dwMsgAndCertEncodingType;
        public uint cCertStore;
        public IntPtr rghCertStore;
        public uint dwFlags;
    }

    /// <summary>
    /// Структура содержит как закодированные, так и декодированные представления маркера метки времени
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct CRYPT_TIMESTAMP_CONTEXT
    {
        public uint cbEncoded;      // DWORD->unsigned int
        public IntPtr pbEncoded;      // BYTE*
        public IntPtr pTimeStamp;     // PCRYPT_TIMESTAMP_INFO->_CRYPT_TIMESTAMP_INFO*
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CERT_ISSUER_SERIAL_NUMBER
    {
        public /*BLOB*/IntPtr Issuer;
        public /*CRYPT_INTEGER_BLOB*/IntPtr SerialNumber;
    }
}