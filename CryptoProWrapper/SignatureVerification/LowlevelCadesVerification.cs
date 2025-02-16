using CryptStructure;
using System.Runtime.InteropServices;

namespace CryptoProWrapper.SignatureVerification
{
    public class LowlevelCadesVerification : IValidateCadesSignature
    {
        private readonly string TSPAddress;
        private IGetCertificate _getCert;

        public LowlevelCadesVerification(
            IGetCertificate getCert)
        {
            string? tspA = "адрес TSP сервера";
 
            if (!string.IsNullOrEmpty(tspA))
            {
                TSPAddress = tspA;
            }

            _getCert = getCert;
        }

        public unsafe SignatureValidationResult VerifySignature(byte[] signMessage, byte[]? data, CadesFormat signatureFormat)
        {
            var result = new SignatureValidationResult();
            nint hMsg = 0;
            nint pInfo = 0;

            try
            {
                hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0U, 0, 0, 0, 0);

                if (hMsg == 0)
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg1 = $"Ошибка открытия криптографического сообщения для декодирования подписи: {error.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка открытия криптографического сообщения для декодирования подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                // load signed CMS
                fixed (byte* pSignMessage = signMessage)
                {
                    string logMsg2 = $"Вызов метода CryptMsgUpdate с параметрами: signMessage.Length = {signMessage.Length}";

                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSignMessage, (uint)signMessage.Length, true))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        string logMsg3 = $"Ошибка загрузки подписи: {error.ErrorMessage}";
                        throw new CapiLiteCoreException($"Ошибка загрузки подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                #region прроверяем открепленная ли подпись
                // Получаем размер подписи
                int mSize = 0;

                if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_CONTENT_PARAM, 0, 0, ref mSize))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg4 = $"Ошибка получения размера подписи подписи: {error.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка получения размера подписи подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                if (mSize == 0)
                {
                    result.IsDetachedSignature = true;
                    hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, Constants.CMSG_DETACHED_FLAG, 0, 0, 0, 0);

                    // load signed CMS
                    fixed (byte* pSignMessage = signMessage)
                    {
                        string logMsg5 = $"Вызов метода CryptMsgUpdate с параметрами: signMessage.Length = {signMessage.Length}";

                        if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSignMessage, (uint)signMessage.Length, true))
                        {
                            var error = ExceptionHelper.GetLastPInvokeError();
                            string logMsg6 = $"Ошибка загрузки подписи: {error.ErrorMessage}";
                            throw new CapiLiteCoreException($"Ошибка загрузки подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                        }
                    }
                }
                #endregion

                if (result.IsDetachedSignature)
                {
                    if (data == null)
                    {
                        string logMsg7 = "Невозможно проверить открепленную подпись без исходных данных";
                        throw new CapiLiteCoreException("Невозможно проверить открепленную подпись без исходных данных", CapiLiteCoreErrors.InternalServerError);
                    }

                    if (data.Length > 0)
                        // load source data
                        fixed (byte* pData = data)
                        {
                            string logMsg8 = $"Вызов метода CryptMsgUpdate с параметрами: data.Length = {data.Length}";

                            if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true))
                            {
                                var error = ExceptionHelper.GetLastPInvokeError();
                                string logMsg9 = $"Ошибка загрузки исходных данных: {error.ErrorMessage}";
                                throw new CapiLiteCoreException($"Ошибка загрузки исходных данных: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                            }
                        }
                    else
                    {
                        string logMsg10 = "Для отсоединенной подписи исходные данные должны быть переданы";
                        throw new CapiLiteCoreException("Для отсоединенной подписи исходные данные должны быть переданы", CapiLiteCoreErrors.BadRequest);
                    }
                }

                // Проверка на соответствие типу CADES_BES при помощи функции CadesMsgIsType.
                // Данная проверка приведена здесь в качестве примера использования
                // функции CadesMsgIsType и не является обязательной при проверке подписи.
                bool bResult = false;
                uint signatureFormatUint = 0;

                switch (signatureFormat)
                {
                    case CadesFormat.CadesBes:
                        signatureFormatUint = Constants.CADES_BES;
                        break;
                    case CadesFormat.CadesT:
                        signatureFormatUint = Constants.CADES_T;
                        break;
                    case CadesFormat.CadesXLongType1:
                        signatureFormatUint = Constants.CADES_X_LONG_TYPE_1;
                        break;
                    case CadesFormat.CadesA:
                        signatureFormatUint = Constants.CADES_A;
                        break;
                }

                string logMsg11 = $"Вызов метода CadesMsgIsType с параметрами: signatureFormatUint = {signatureFormatUint}";

                if (!CadesHelper.CadesMsgIsType(hMsg, 0, signatureFormatUint, out bResult))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg12 = $"Ошибка проверки фориата подписи: {error.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка проверки фориата подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                var verificationPara = new CADES_VERIFICATION_PARA();
                verificationPara.dwSize = (uint)Marshal.SizeOf(verificationPara);

                switch (signatureFormat)
                {
                    case CadesFormat.CadesT:
                        result.SignatureFormat = "CADES-T";
                        verificationPara.dwCadesType = Constants.CADES_T;
                        break;
                    case CadesFormat.CadesXLongType1:
                        result.SignatureFormat = "CADES-X-LONG-TYPE-1";
                        verificationPara.dwCadesType = Constants.CADES_X_LONG_TYPE_1;
                        break;
                    case CadesFormat.CadesA:
                        result.SignatureFormat = "CADES-A";
                        verificationPara.dwCadesType = Constants.CADES_A;
                        break;
                    default:
                        result.SignatureFormat = "CADES-BES";
                        verificationPara.dwCadesType = Constants.CADES_BES;
                        break;
                }

                // Проверяем подпись сообщения
                PInvokeExcetion PInvokeExcetion;

                if (!CadesHelper.CadesMsgVerifySignature(hMsg, 0, (nint)(&verificationPara), out pInfo))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg17 = $"Ошибка проверки подписи: {error.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка проверки подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                PInvokeExcetion = ExceptionHelper.GetCadesVerificationError(pInfo);

                if (PInvokeExcetion.LastErrorCode == Constants.ADES_VERIFY_SUCCESS)
                {
                    result.IsSignatureValid = true;
                }
                else
                {
                    result.IsSignatureValid = false;
                    result.SignatureFormat = string.Empty;
                    result.Error = PInvokeExcetion.ErrorMessage;
                }
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg19 = $"Ошибка проверки подписи: {ex.Message}";
                throw;
            }
            finally
            {
                if (hMsg != 0 && !Crypt32Helper.CryptMsgClose(hMsg))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg20 = $"Ошибка освобождения контекста дескриптора сообщения: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }

                if (pInfo != 0 && !CadesHelper.CadesFreeVerificationInfo(pInfo))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg21 = $"Ошибка освобождения структуры PCADES_VERIFICATION_INFO: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }

            return result;
        }
    }
}
