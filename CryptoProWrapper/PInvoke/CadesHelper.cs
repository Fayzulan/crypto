using CryptStructure;
using System.Runtime.InteropServices;

namespace CryptoProWrapper
{
    public class CadesHelper
    {
        /// <summary>
        /// Создает хэш указанного содержимого, подписывает хэш, а затем кодирует исходное содержимое сообщения и подписанный хэш
        /// </summary>
        /// <param name="pSignPara">Параметры подписи</param>
        /// <param name="fDetachedSignature">Значение TRUE , если это должна быть отсоединяемая подпись</param>
        /// <param name="cToBeSigned">Кол-во сообщений</param>
        /// <param name="rgpbToBeSigned">Массив указателей на буфер сообщений</param>
        /// <param name="rgcbToBeSigned">Массив длин массива сообщений</param>
        /// <param name="ppSignedBlob"> Указатель на указатель на структуру CRYPT_DATA_BLOB, в которой возвращается закодированное подписанное сообщение.</param>
        /// <returns></returns>
        [DllImport(OSHelper.CADES, EntryPoint = "CadesSignMessage", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool CadesSignMessage([In] nint pSignPara, [In] bool fDetachedSignature, uint cToBeSigned, [In] nint rgpbToBeSigned, uint rgcbToBeSigned,
          ref nint ppSignedBlob);

        [DllImport(OSHelper.CADES, EntryPoint = "CadesFreeBlob", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        internal static extern bool CadesFreeBlob(IntPtr pBlob);

        /// <summary>
        /// Открывает дескриптор сообщения для создания усовершенствованной подписи
        /// Эта функция добавляет к подписанным атрибутам идентификатор сертификата подписи (атрибут signing-certificate или signing-certificate-v2), 
        /// необходимый для формата CAdES BES, а затем вызывает CryptMsgOpenToEncode. 
        /// Используется вместо CryptMsgOpenToEncode  при создании сообщения с усовершенствованной подписью.
        /// </summary>
        /// <param name="dwMsgEncodingType">Указывает используемый тип кодирования</param>
        /// <param name="dwFlags">Поведение метода</param>
        /// <param name="pvMsgEncodeInfo"> Указатель на структуру CADES_ENCODE_INFO</param>
        /// <param name="pszInnerContentObjID"></param>
        /// <param name="pStreamInfo"></param>
        /// <returns></returns>
        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern nint CadesMsgOpenToEncode([In] uint dwMsgEncodingType, [In] uint dwFlags,
            [In] nint pvMsgEncodeInfo, [In][MarshalAs(UnmanagedType.LPStr)] string? pszInnerContentObjID, [In] nint pStreamInfo);

        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesVerifyMessage(
           ref CryptStructure.CADES_VERIFY_MESSAGE_PARA pVerifyPara,
           uint dwSignerIndex,
           byte[] pbSignedBlob,
           uint cbSignedBlob,
           ref IntPtr ppDecodedBlob,
           ref /*CADES_VERIFICATION_INFO*/IntPtr ppVerificationInfo
        );

        [DllImport(OSHelper.CADES)]
        internal static extern bool CadesFreeVerificationInfo(/*CADES_VERIFICATION_INFO*/IntPtr pVerificationInfo);

        /// <summary>
        /// Низкоуровневая функция отображения окна свойств УЭЦП
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор подписанного сообщения, должен быть открыт с помощью CryptMsgOpenToDecode.</param>
        /// <param name="dwSignatureIndex">Индекс подписи, для которой будет отображено окно свойств.</param>
        /// <param name="hwndParent">Дескриптор родительского окна для окна со списком свойств УЭЦП. Если данный параметр равен NULL, то родительским окном будет рабочий стол Microsoft Windows.</param>
        /// <param name="title"> Если задан, заменяет используемый по умолчанию заголовок окна.</param>
        /// <returns></returns>
        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesMsgUIDisplaySignature([In] nint hCryptMsg, [In] uint dwSignatureIndex, [In] nint hwndParent,
            [In][MarshalAs(UnmanagedType.LPStr)] string? title);


        /// <summary>
        /// 
        /// </summary>
        /// <param name="pCadesViewSignaturePara"></param>
        /// <param name="dwSignatureIndex"></param>
        /// <param name="pbDetachedSignBlob"></param>
        /// <param name="cbDetachedSignBlob"></param>
        /// <param name="cToBeSigned"></param>
        /// <param name="rgpbToBeSigned"></param>
        /// <param name="rgcbToBeSigned"></param>
        /// <param name="prgPropPages"></param>
        /// <param name="pcPropPages"></param>
        /// <returns></returns>
        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesViewSignatureDetached([In] PCADES_VIEW_SIGNATURE_PARA pCadesViewSignaturePara, [In] uint dwSignatureIndex, [In] nint pbDetachedSignBlob,
            [In] uint cbDetachedSignBlob, [In] uint cToBeSigned, [In] nint rgpbToBeSigned, [In] uint rgcbToBeSigned, [Out] out nint prgPropPages, [Out] out uint pcPropPages);

        /// <summary>
        /// Проверяет усовершенствованную подпись сообщения
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор подписанного сообщения</param>
        /// <param name="dwSignatureIndex">Номер проверяемой подписи</param>
        /// <param name="pVerificationPara"><Указатель на структуру CADES_VERIFICATION_PARA. В этой структуре может быть указан тип подписи, соответствие которому следует проверить/param>
        /// <param name="ppVerificationInfo">Указатель на указатель на структуру CADES_VERIFICATION_INFO. В этой структуре возвращается дополнительная информация о подписи после проверки.</param>
        /// <returns></returns>
        /// <remarks>https://cpdn.cryptopro.ru/content/cades/group___low_level_cades_a_p_i_gcf49a28c5cff667f1d208194ff2e7b50_1gcf49a28c5cff667f1d208194ff2e7b50.html</remarks>
        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesMsgVerifySignature([In] nint hCryptMsg, [In] uint dwSignatureIndex, [In] nint pVerificationPara, out nint ppVerificationInfo);

        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesMsgAddEnhancedSignature([In] nint hCryptMsg, [In] nint pCadesCosignPara);

        /// <summary>
        /// Проверяет соответствие заданному типу усовершенствованной подписи
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор подписанного сообщения</param>
        /// <param name="dwSignatureIndex">Номер обрабатываемой подписи</param>
        /// <param name="dwCadesType">Необходимый тип усовершенствованной подписи</param>
        /// <param name="pbResult">Результат проверки. Заполняется при успешном завершении функции. TRUE означает, что подпись соответствует заданному типу/param>
        /// <returns></returns>
        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesMsgIsType([In] nint hCryptMsg, [In] uint dwSignatureIndex, [In] uint dwCadesType, out bool pbResult);

        /// <summary>
        /// Функция создания усовершенствованной подписи
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор подписанного сообщения, должен быть открыт с помощью CryptMsgOpenToDecode</param>
        /// <param name="dwSignatureIndex">Номер обрабатываемой подписи.</param>
        /// <param name="pCadesSignPara">Указатель на структуру CADES_SIGN_PARA, задающую параметры создания усовершенствованной подписи.</param>
        /// <returns></returns>
        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesMsgEnhanceSignature([In] nint hCryptMsg, [In] uint dwSignatureIndex, [In] nint pCadesSignPara);

        /// <summary>
        /// Функция создания усовершенствованной подписи для всех подписей в сообщении
        /// </summary>
        /// <param name="hCryptMsg">Дескриптор подписанного сообщения, должен быть открыт с помощью CryptMsgOpenToDecode</param>
        /// <param name="pCadesSignPara">Указатель на структуру CADES_SIGN_PARA, задающую параметры создания усовершенствованной подписи.</param>
        /// <returns></returns>
        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CadesMsgEnhanceSignatureAll([In] nint hCryptMsg, [In] nint pCadesSignPara);

        [DllImport(OSHelper.CADES, CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CadesMsgGetSigningCertId(
            /*HCRYPTMSG*/IntPtr hCryptMsg,
            uint dwSignatureIndex,
            out /*PCRYPT_DATA_BLOB*/IntPtr ppCertId
        );
    }

}
