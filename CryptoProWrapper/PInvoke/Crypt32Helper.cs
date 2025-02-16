using CryptStructure;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Text;

namespace CryptoProWrapper
{
    public class Crypt32Helper
    {
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true, EntryPoint = "CertOpenSystemStore" + OSHelper.OSPosfix)]
        internal static extern IntPtr CertOpenSystemStore(
            IntPtr hProv, // HCRYPTPROV
            string pszSubsystemProtocol
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern unsafe bool CryptDecodeObject(
            uint dwCertEncodingType,
            IntPtr lpszStructType,
            byte* pbEncoded,
            int cbEncoded,
            int dwFlags,
            void* pvStructInfo,
            ref int pcbStructInfo
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern unsafe bool CertSetCertificateContextProperty(
            IntPtr pCertContext,
            int dwPropId,
            int dwFlags,
            [In] CRYPT_KEY_PROV_INFO* pvData
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CertGetCertificateContextProperty(
            IntPtr pCertContext, // PCCERT_CONTEXT
            uint dwPropId,
            IntPtr pvData,
            ref uint pcbData
        );

        [DllImport(OSHelper.Crypt32, SetLastError = true),
         SuppressUnmanagedCodeSecurity,
         ResourceExposure(ResourceScope.None)]
        internal static extern void CertFreeCertificateChain(IntPtr handle);

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        [ResourceExposure(ResourceScope.None)]
        internal static extern IntPtr CertCreateCertificateContext(
                uint dwCertEncodingType,
                byte[] pbCertEncoded,
                uint cbCertEncoded);
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        [ResourceExposure(ResourceScope.None)]
        internal static extern IntPtr CertCreateCertificateContext(
               uint dwCertEncodingType,
               nint pbCertEncoded,
               uint cbCertEncoded);

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        [ResourceExposure(ResourceScope.None)]
        internal extern static bool CertAddCertificateContextToStore(
                IntPtr hCertStore,
                IntPtr pCertContext,
                uint dwAddDisposition,
                IntPtr ppStoreContext);
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal extern static bool CertAddCertificateContextToStore(
            IntPtr hCertStore,
            IntPtr pCertContext,
            uint dwAddDisposition,
            out IntPtr ppStoreContext
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        [ResourceExposure(ResourceScope.None)]
        internal static extern bool CertFreeCertificateContext([In] IntPtr pCertContext);

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CertVerifyCertificateChainPolicy(
            IntPtr pszPolicyOID,
            IntPtr pChainContext,
            ref CryptStructure.CERT_CHAIN_POLICY_PARA pPolicyPara,
            ref CryptStructure.CERT_CHAIN_POLICY_STATUS pPolicyStatus
        );

        [DllImport(OSHelper.Crypt32, SetLastError = true)]
        internal static extern bool CertGetCertificateChain(
            IntPtr hChainEngine,
            IntPtr pCertContext,
            IntPtr pTime,
            IntPtr hAdditionalStore,
            CryptStructure.CertChainParameters pChainPara,
            int dwFlags,
            IntPtr pvReserved,
            out IntPtr ppChainContext
        );

        internal static string GetErrorDescription(uint errorCode)
        {
            //string messageBuffer;
            StringBuilder messageBuffer = new StringBuilder(256);
            uint result = Kernel32Helper.FormatMessage(
                0x00001000 | 0x00000200 | 0x00000100,
                IntPtr.Zero,
                errorCode,
                0x0419,//0x0409, // English (United States) language
                out messageBuffer,
                messageBuffer.Capacity,
                IntPtr.Zero);

            if (result == 0)
            {
                return "Failed to retrieve error description";
            }
            else
            {
                return messageBuffer.ToString().Trim();
            }
        }

        /// <summary>
        /// Создает контекстсписка отзыва сертификатов (CRL) из закодированного списка отзыва сертификатов.
        /// </summary>
        /// <param name="dwCertEncodingType">Указывает тип используемой кодировки.</param>
        /// <param name="pbCrlEncoded">Указатель на буфер, содержащий закодированный список отзыва сертификатов, из которого создается контекст.</param>
        /// <param name="cbCrlEncoded">Размер буфера pbCrlEncoded (в байтах).</param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint CertCreateCRLContext(uint dwCertEncodingType, nint pbCrlEncoded, uint cbCrlEncoded);

        [DllImport(OSHelper.Crypt32, SetLastError = true)]
        internal static extern bool CertFreeCRLContext(IntPtr pCrlContext);

        /// <summary>
        /// Функция CertAddCRLContextToStore добавляет контекст списка отзыва сертификатов (CRL) в указанное хранилище сертификатов
        /// </summary>
        /// <param name="hCertStore">Дескриптор хранилища сертификатов</param>
        /// <param name="pCrlContext">Указатель на добавляемую структуру CRL_CONTEXT</param>
        /// <param name="dwAddDisposition">Указывает действие, которое необходимо выполнить, если соответствующий список отзыва сертификатов или ссылка на соответствующий список отзыва сертификатов уже существует в хранилище.
        /// Для КриптоПро dwAddDisposition поддерживаются только следующие значения: CERT_STORE_ADD_NEW, CERT_STORE_ADD_REPLACE_EXISTING, CERT_STORE_ADD_ALWAYS</param>
        /// <param name="ppStoreContext">Указатель на указатель на декодированный контекст списка отзыва сертификатов. Это необязательный параметр, который может иметь значение NULL,
        /// указывая, что вызывающей приложению не требуется копия добавленного или существующего списка отзыва сертификатов. 
        /// Если копия сделана, этот контекст должен быть освобожден с помощью CertFreeCRLContext.</param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, SetLastError = true)]
        internal static extern bool CertAddCRLContextToStore(nint hCertStore, nint pCrlContext, uint dwAddDisposition, nint ppStoreContext);

        /// <summary>
        /// Получает закрытый ключ для сертификата
        /// </summary>
        /// <param name="pCert">Контекст сертификата</param>
        /// <param name="dwFlags">Набор флагов, которые изменяют поведение этой функции</param>
        /// <param name="pvReserved">Если задано CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG , это адрес HWND. Если CRYPT_ACQUIRE_WINDOW_HANDLE_FLAG не задан, этот параметр должен иметь значение NULL</param>
        /// <param name="phCryptProv">Получает дескриптор поставщика CryptoAPI или ключ CNG. Если переменная pdwKeySpec получает флаг CERT_NCRYPT_KEY_SPEC , это дескриптор ключа CNG типа NCRYPT_KEY_HANDLE; В противном случае это дескриптор поставщика CryptoAPI типа HCRYPTPROV</param>
        /// <param name="pdwKeySpec">Получает дополнительные сведения о ключе</param>
        /// <param name="pfCallerFreeProv">Указывает, должен ли вызывающий объект освободить дескриптор, возвращенный в переменной phCryptProv</param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptAcquireCertificatePrivateKey([In] nint pCert, [In] uint dwFlags, [In] nint pvReserved
            , out nint phCryptProv, out uint pdwKeySpec, out bool pfCallerFreeProv);

        /// <summary>
        /// Пополняет текст криптографического сообщения. Использование этой функции позволяет строить криптографическое сообщение шаг за шагом путем 
        /// повторных вызовов функции CryptMsgUpdate. Добавленный текст сообщения является либо закодированным, либо раскодированным в зависимости от того, 
        /// было ли сообщение открыто функцией CryptMsgOpenToEncode или функцией CryptMsgOpenToDecode
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор криптографического сообщения для обновления</param>
        /// <param name="pbData">Указатель на буфер, содержащий данные для кодирования или декодирования</param>
        /// <param name="cbData">Количество байтов данных в буфере pbData</param>
        /// <param name="fFinal">Указывает, что обрабатывается последний блок данных для кодирования или декодирования</param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptMsgUpdate([In] nint hCryptMsg, [In] nint pbData, [In] uint cbData, [In] bool fFinal);

        /// <summary>
        /// Закрывает дескриптор криптографичекого сообщения
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор криптографичекого сообщения</param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, SetLastError = true)]
        internal static extern bool CryptMsgClose(IntPtr hCryptMsg);

        /// <summary>
        /// Получает параметр сообщения после того, как криптографическое сообщение было раскодировано или закодировано. 
        /// Эта функция вызывается после последнего вызова функции CryptMsgUpdate
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор криптографического сообщения</param>
        /// <param name="dwParamType">Указывает типы параметров извлекаемых данных</param>
        /// <param name="dwIndex">Индекс извлекаемого параметра, если применимо. Если параметр не извлекается, этот параметр игнорируется и имеет значение 0</param>
        /// <param name="pvData">Указатель на буфер, который получает полученные данные. Форма этих данных зависит от значения параметра dwParamType .</param>
        /// <param name="pcbData">Указывает размер (в байтах) буфера, на который указывает параметр pvData </param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptMsgGetParam([In] nint hCryptMsg, [In] uint dwParamType, [In] uint dwIndex, [In] nint pvData, ref int pcbData);
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptMsgGetParam([In] nint hCryptMsg, [In] uint dwParamType, [In] uint dwIndex, [In] byte[] pvData, ref int pcbData);

        /// <summary>
        /// Открывает криптографическое сообщение для кодирования и возвращает дескриптор открытого сообщения.
        /// </summary>
        /// <param name="dwMsgEncodingType">Указывает используемый тип кодирования.</param>
        /// <param name="dwFlags">Поведение метода</param>
        /// <param name="dwMsgType">Указывает тип сообщения</param>
        /// <param name="pvMsgEncodeInfo">Адрес структуры, содержащей сведения о кодировке</param>
        /// <param name="pszInnerContentObjID"></param>
        /// <param name="pStreamInfo"></param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint CryptMsgOpenToEncode([In] uint dwMsgEncodingType, [In] uint dwFlags, [In] uint dwMsgType,
            [In] nint pvMsgEncodeInfo, [In][MarshalAs(UnmanagedType.LPStr)] string? pszInnerContentObjID, [In] nint pStreamInfo);

        [DllImport(OSHelper.Crypt32)]
        internal static extern bool CryptVerifyMessageSignature(
            ref CRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
            uint dwSignerIndex,
            byte[] pbSignedBlob,
            uint cbSignedBlob,
            byte[]? pbDecoded,
            ref uint pcbDecoded,
            nint ppSignerCert
        );

        [DllImport(OSHelper.Crypt32)]
        internal static extern bool CryptVerifyDetachedMessageSignature(
            ref CRYPT_VERIFY_MESSAGE_PARA pVerifyPara,
            uint dwSignerIndex,
            byte[] pbDetachedSignBlob,
            uint cbDetachedSignBlob,
            uint cToBeSigned,
            byte[] rgpbToBeSigned,
            ref uint rgcbToBeSigned,
            /*PCCERT_CONTEXT*/IntPtr ppSignerCert
        );

        /// <summary>
        /// Открывает криптографическое сообщение для декодирования и возвращает дескриптор открытого сообщения
        /// </summary>
        /// <param name="dwMsgEncodingType">Тип кодирования</param>
        /// <param name="dwFlags">Поведение метода</param>
        /// <param name="dwMsgType">Тип декодированного сообщения</param>
        /// <param name="hCryptProv">Этот параметр не используется</param>
        /// <param name="pRecipientInfo">Этот параметр не используется</param>
        /// <param name="pStreamInfo">Указатель на структуру CMSG_STREAM_INFO , которая содержит указатель на обратный вызов</param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, SetLastError = true)]
        internal static extern nint CryptMsgOpenToDecode(
            uint dwMsgEncodingType,
            uint dwFlags,
            uint dwMsgType,
            nint hCryptProv,
            nint pRecipientInfo,
            nint pStreamInfo
            );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CryptSignMessage(
            ref CRYPT_SIGN_MESSAGE_PARA pSignPara,
            bool fDetachedSignature,
            uint cToBeSigned,
            IntPtr[] rgpbToBeSigned,
            uint rgcbToBeSigned,
            byte[] pbSignedBlob,
            ref uint pcbSignedBlob
        );

        /// <summary>
        ///  Выполняет контрольное действие после того, как сообщение было раскодировано последним вызовом функции CryptMsgUpdate. 
        ///  Контрольные операции, обеспеченные этой функцией, используются при расшифровании, проверке электронной подписи и хеша, а также при добавлении и удалении сертификатов, 
        ///  СОС, подписей и недостоверных атрибутов.
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор криптографического сообщения</param>
        /// <param name="dwFlags">Флаг поведения метода</param>
        /// <param name="dwCtrlType">Тип выполняемой операции</param>
        /// <param name="pvCtrlPara">Указатель на структуру, определяемую значением dwCtrlType.</param>
        /// <returns>Если функция завершается сбоем, возвращаемое значение равно нулю</returns>
        /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptmsgcontrol</remarks>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptMsgControl(
            [In] nint hCryptMsg,
            [In] uint dwFlags,
            [In] uint dwCtrlType,
            [In] nint pvCtrlPara
        );

        /// <summary>
        /// Открывает хранилище сертификатов
        /// </summary>
        /// <param name="lpszStoreProvider">Указатель на строку ANSI, которая содержит тип поставщика хранилища.</param>
        /// <param name="dwEncodingType">Указывает тип кодирования сертификата и тип кодирования сообщений</param>
        /// <param name="hCryptProv">Этот параметр не используется</param>
        /// <param name="dwFlags">Задает расположение хранилища</param>
        /// <param name="pvPara">32-разрядное значение, которое может содержать дополнительные сведения для этой функции</param>
        /// <returns>Если функция выполняется успешно, функция возвращает дескриптор в хранилище сертификатов</returns>
        /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certopenstore</remarks>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint CertOpenStore(
            [In] nint lpszStoreProvider,
            [In] uint dwEncodingType,
            [In] nint hCryptProv,
            [In] uint dwFlags,
            [In] nint pvPara
        );
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern nint CertOpenStore(
            [In] nint lpszStoreProvider,
            [In] uint dwEncodingType,
            [In] nint hCryptProv,
            [In] uint dwFlags,
            [In, MarshalAs(UnmanagedType.LPStr)] String pvPara
        );

        /// <summary>
        /// Handle of the certificate store to be closed
        /// </summary>
        /// <param name="hCertStore">Handle of the certificate store to be closed</param>
        /// <param name="dwFlags">Typically, this parameter uses the default value zero. The default is to close the store with memory remaining allocated for contexts that have not been freed. 
        /// In this case, no check is made to determine whether memory for contexts remains allocated.</param>
        /// <returns>If the function succeeds, the return value is TRUE</returns>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertCloseStore(
            [In] nint hCertStore,
            [In] uint dwFlags);

        /// <summary>
        /// Finds the first or next certificate context in a certificate store that matches a search criteria established by the dwFindType and its associated pvFindPara.
        /// This function can be used in a loop to find all of the certificates in a certificate store that match the specified find criteria.
        /// </summary>
        /// <param name="hCertStore">A handle of the certificate store to be searched.</param>
        /// <param name="dwCertEncodingType">Specifies the type of encoding used.</param>
        /// <param name="dwFindFlags">Used with some dwFindType values to modify the search criteria. For most dwFindType values, dwFindFlags is not used and should be set to zero.</param>
        /// <param name="dwFindType">Specifies the type of search being made. The search type determines the data type, contents, and the use of pvFindPara.</param>
        /// <param name="pvFindPara">Points to a data item or structure used with dwFindType.</param>
        /// <param name="pPrevCertContext">A pointer to the last <see cref="CERT_CONTEXT"/> structure returned by this function. This parameter must be NULL on the first call of the function. 
        /// To find successive certificates meeting the search criteria, set pPrevCertContext to the pointer returned by the previous call to the function. 
        /// This function frees the <see cref="CERT_CONTEXT"/> referenced by non-NULL values of this parameter.</param>
        /// <returns>If the function succeeds, the function returns a pointer to a read-only <see cref="CERT_CONTEXT"/> structure.
        /// If the function fails and a certificate that matches the search criteria is not found, the return value is NULL.</returns>
        /// <remarks>https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certfindcertificateinstore</remarks>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint CertFindCertificateInStore(
            [In] nint hCertStore,
            [In] uint dwCertEncodingType,
            [In] uint dwFindFlags,
            [In] uint dwFindType,
            [In] nint pvFindPara,
            [In] nint pPrevCertContext);
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint CertFindCertificateInStore(
            [In] nint hCertStore,
            [In] uint dwCertEncodingType,
            [In] uint dwFindFlags,
            [In] uint dwFindType,
            [In, MarshalAs(UnmanagedType.LPWStr)] string pvFindPara,
            [In] nint pPrevCertContext);

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CertDeleteCertificateFromStore(
            IntPtr pCertContext // PCCERT_CONTEXT
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CertEnumCertificatesInStore(
            IntPtr hCertStore, // HCERTSTORE
            IntPtr pPrevCertContext // PCCERT_CONTEXT
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CertDeleteCRLFromStore(IntPtr pCrlContext);

        /// <summary>
        /// Кодирует структуру
        /// </summary>
        /// <param name="pCrlContext"></param>
        /// <returns></returns>
        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptEncodeObjectEx(
            [In] nint dwCertEncodingType,
            [In, MarshalAs(UnmanagedType.LPStr)] string lpszStructType,
            [In] nint pvStructInfo,
            [In] uint dwFlags,
            [In] nint pEncodePara,
            [Out] nint pvEncoded,
            [Out] nint pcbEncoded
            );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptSetKeyParam(
            IntPtr hKey,
            uint dwParam,
            byte[] pbData,
            uint dwFlags
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptEncryptMessage(
          /*PCRYPT_ENCRYPT_MESSAGE_PARA*/IntPtr pEncryptPara,
          uint cRecipientCert,
          /*PCCERT_CONTEXT[]*/IntPtr[] rgpRecipientCert,
          /*const BYTE**/byte[] pbToBeEncrypted,
          uint cbToBeEncrypted,
          byte[]? pbEncryptedBlob,
          ref uint pcbEncryptedBlob
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptDecryptMessage(
            ref CRYPT_DECRYPT_MESSAGE_PARA pDecryptPara,
            byte[] pbEncryptedBlob,
            uint cbEncryptedBlob,
            [In, Out] byte[]? pbDecrypted,
            ref uint pcbDecrypted,
            IntPtr ppXchgCert
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CertEnumCRLsInStore(
            IntPtr hCertStore, // HCERTSTORE
            IntPtr pPrevCrlContext // PCCRL_CONTEXT
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern unsafe IntPtr CertFindExtension(
            [MarshalAs((UnmanagedType)20)] string pszObjId,
            int cExtensions,
            Crypto.CERT_EXTENSION* rgExtensions
        );

        [DllImport(OSHelper.Crypt32, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern unsafe int CertNameToStr(
            int dwCertEncodingType,
            byte[] pName,
            int dwStrType,
            char* psz,
            int csz
        );
    }
}
