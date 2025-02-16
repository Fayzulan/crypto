using CryptStructure;
using System.Runtime.InteropServices;

namespace CryptoProWrapper
{
    /// <summary>
    /// Обработанная ошибка pinvoke
    /// </summary>
    public struct PInvokeExcetion
    {
        public uint LastErrorCode;
        public string SystemErrorDescription;
        public string ErrorMessage;
    }

    public static class ExceptionHelper
    {
        /// <summary>
        /// Получение ошибки pinvoke
        /// </summary>
        /// <returns></returns>
        public static PInvokeExcetion GetLastPInvokeError()
        {
            var PInvokeExcetion = new PInvokeExcetion
            {
                LastErrorCode = Kernel32Helper.GetLastError()
            };

            PInvokeExcetion.SystemErrorDescription = Crypt32Helper.GetErrorDescription(PInvokeExcetion.LastErrorCode);

            switch (PInvokeExcetion.LastErrorCode)
            {
                case 2148204810:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. Не удалось построить цепочку сертификатов для доверенного корневого центра.";
                    break;
                case 2147943865:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. Ошибка чтения XML файла";
                    break;
                case 3255828800:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. Истек срок лицензии TSP клиента";
                    break;
                case 2148073494:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. Не удается получить доступ к закрытому ключу";
                    break;
                case 2148532331:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. Введен неправильный PIN-код";
                    break;
                case 2148073498:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. Неправильный зарегистрированный набор ключей";
                    break;
                case 3255894305:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. В сертификате не найден адрес OCSP сервиса";
                    break;
                case 2148204801:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. Истек/не наступил срок действия требуемого сертификата";
                    break;
                default:
                    PInvokeExcetion.ErrorMessage = $"{PInvokeExcetion.LastErrorCode}. {PInvokeExcetion.SystemErrorDescription}";
                    break;
            }

            return PInvokeExcetion;
        }

        /// <summary>
        /// Получение ошибки проверки подписи CADES
        /// </summary>
        /// <param name="pInfo"></param>
        /// <returns></returns>
        public static PInvokeExcetion GetCadesVerificationError(nint pInfo)
        {
            var PInvokeExcetion = new PInvokeExcetion();
            var lastPInvokeError = GetLastPInvokeError();

            if (pInfo == 0)
            {
                PInvokeExcetion = lastPInvokeError;
            }

            PCADES_VERIFICATION_INFO? strVerInfo = (PCADES_VERIFICATION_INFO?)Marshal.PtrToStructure(pInfo, typeof(PCADES_VERIFICATION_INFO));

            if (strVerInfo == null)
            {
                PInvokeExcetion = lastPInvokeError;
            }
            else
            {
                PInvokeExcetion.LastErrorCode = strVerInfo.Value.dwStatus;
                PInvokeExcetion.ErrorMessage = $"{GetVerificationInfo(strVerInfo.Value.dwStatus)}. {lastPInvokeError.ErrorMessage}";
                PInvokeExcetion.SystemErrorDescription = lastPInvokeError.SystemErrorDescription;
            }

            return PInvokeExcetion;
        }

        /// <summary>
        /// Получение ошибки проверки подписи XADES
        /// </summary>
        /// <param name="pInfo"></param>
        /// <returns></returns>
        public static PInvokeExcetion GetXadesVerificationError(nint pInfo)
        {
            var PInvokeExcetion = new PInvokeExcetion();

            if (pInfo == 0)
            {
                PInvokeExcetion = GetLastPInvokeError();
            }

            var strBlob2 = Marshal.PtrToStructure(pInfo, typeof(XADES_VERIFICATION_INFO_ARRAY));

            if (strBlob2 is XADES_VERIFICATION_INFO_ARRAY strBlobStruct2)
            {
                var verInfoStr = Marshal.PtrToStructure(strBlobStruct2.pXadesVerificationInfo, typeof(XADES_VERIFICATION_INFO));

                if (verInfoStr is XADES_VERIFICATION_INFO verInfo)
                {
                    PInvokeExcetion.LastErrorCode = verInfo.dwStatus;
                    PInvokeExcetion.ErrorMessage = GetVerificationInfo(verInfo.dwStatus);
                }
            }

            return PInvokeExcetion;
        }

        private static string GetVerificationInfo(uint status)
        {
            switch (status)
            {
                case 0://ADES_VERIFY_SUCCESS
                    return "Успешная проверка подписи.";
                case 1://ADES_VERIFY_INVALID_REFS_AND_VALUES
                    return "Отсутствуют или имеют неправильный формат атрибуты со ссылками и значениями доказательств подлинности.";
                case 2://ADES_VERIFY_SIGNER_NOT_FOUND
                    return "Сертификат, на ключе которого было подписано сообщение, не найден.";
                case 3://ADES_VERIFY_NO_VALID_SIGNATURE_TIMESTAMP
                    return "В сообщении не найден действительный штамп времени на подпись.";
                case 4://ADES_VERIFY_REFS_AND_VALUES_NO_MATCH
                    return "Значения ссылок на доказательства подлинности и сами доказательства, вложенные в сообщение, не соответствуют друг другу.";
                case 5://ADES_VERIFY_NO_CHAIN
                    return "Не удалось построить цепочку для сертификата, на ключе которого подписано сообщение.";
                case 6://ADES_VERIFY_END_CERT_REVOCATION
                    return "Ошибка проверки конечного сертификата на отзыв.";
                case 7://ADES_VERIFY_CHAIN_CERT_REVOCATION
                    return "Ошибка проверки сертификата цепочки на отзыв.";
                case 8://ADES_VERIFY_BAD_SIGNATURE
                    return "Сообщение содержит неверную подпись.";
                case 9://ADES_VERIFY_NO_VALID_CADES_C_TIMESTAMP
                    return "В сообщении не найден действительный штамп времени на доказательства подлинности подписи.";
                case 10://ADES_VERIFY_BAD_POLICY
                    return "";
                case 11://ADES_VERIFY_UNSUPPORTED_ATTRIBUTE
                    return "";
                case 12://ADES_VERIFY_FAILED_POLICY
                    return "";
                case 13://ADES_VERIFY_ECONTENTTYPE_NO_MATCH
                    return "Значение подписанного атрибута content-type не совпадает со значением, указанным в поле encapContentInfo.eContentType.";
                case 14://ADES_VERIFY_NO_VALID_ARCHIVE_TIMESTAMP
                    return "В сообщении не найден архивный штамп времени на подпись.";
                default:
                    return $"VERIFICATION_INFO.dwStatus = {status}";
            }
        }
    }
}
