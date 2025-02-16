using CryptStructure;
using System.Runtime.InteropServices;

namespace CryptoProWrapper.SignatureVerification
{
    public class XadesSignatureVerification : IValidateXadesSignature
    {
        public SignatureValidationResult VerifySignature(byte[] signMessage, byte[]? data, XadesFormat signatureFormat)
        {
            nint blob = 0;            
            var signatureValidationResult = new SignatureValidationResult();
            var verifyPara = new XADES_VERIFY_MESSAGE_PARA();

            try
            {
                uint dSignatureFormat = 0;

                switch (signatureFormat)
                {
                    case XadesFormat.XadesBes:
                        dSignatureFormat = Constants.XADES_BES;
                        break;
                    case XadesFormat.XadesT:
                        dSignatureFormat = Constants.XADES_T;
                        break;
                    case XadesFormat.XadesXLongType1:
                        dSignatureFormat = Constants.XADES_X_LONG_TYPE_1;
                        break;
                    //case XadesFormat.XadesA:
                    //    dSignatureFormat = Constants.XADES_A;
                    //    break;
                    case XadesFormat.XadesXMLDSIG:
                        dSignatureFormat = Constants.XADES_XMLDSIG;
                        break;
                    case XadesFormat.XadesNone:
                        dSignatureFormat = Constants.XADES_NONE;
                        break;
                }

                XADES_VERIFICATION_PARA xadesVerifyPara = new XADES_VERIFICATION_PARA();
                xadesVerifyPara.dwSize = (uint)Marshal.SizeOf(typeof(XADES_VERIFICATION_PARA));
                xadesVerifyPara.dwSignatureType = dSignatureFormat;
                verifyPara.pXadesVerifyPara = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(XADES_VERIFICATION_PARA)));
                Marshal.StructureToPtr(xadesVerifyPara, verifyPara.pXadesVerifyPara, false);
                verifyPara.dwSize = (uint)Marshal.SizeOf(typeof(XADES_VERIFY_MESSAGE_PARA));
                PInvokeExcetion PInvokeExcetion;
                string logMsg1 = $"Вызов метода XadesVerify с параметрами: dSignatureFormat = {dSignatureFormat}, signMessage.Length = {signMessage.Length}";

                if (!XadesHelper.XadesVerify(
                   ref verifyPara,
                   null,
                   signMessage,
                   (uint)signMessage.Length,
                   ref blob
                ))
                {
                    PInvokeExcetion = ExceptionHelper.GetXadesVerificationError(blob);
                    throw new Exception($"Could not verify signature. Details: {PInvokeExcetion.ErrorMessage}");
                }

                PInvokeExcetion = ExceptionHelper.GetXadesVerificationError(blob);

                if (PInvokeExcetion.LastErrorCode > 0)
                {
                    throw new Exception($"Signature is invalid. Details: {PInvokeExcetion.ErrorMessage}.");
                }

                if (PInvokeExcetion.LastErrorCode == Constants.ADES_VERIFY_SUCCESS)
                {
                    signatureValidationResult.IsSignatureValid = true;
                }
                else
                {
                    signatureValidationResult.IsSignatureValid = false;
                    signatureValidationResult.SignatureFormat = string.Empty;
                    signatureValidationResult.Error = PInvokeExcetion.ErrorMessage;
                }
            }
            catch (CapiLiteCoreException ex)
            {
                signatureValidationResult.Error = ex.Message;
                signatureValidationResult.IsSignatureValid = false;
                signatureValidationResult.SignatureFormat = string.Empty;
                throw;
            }
            catch (Exception ex)
            {
                string logMsg2 = $"Ошибка проверки подписи xades: {ex.Message}";
                signatureValidationResult.Error = "Ошибка проверки подписи";
                signatureValidationResult.IsSignatureValid = false;
                signatureValidationResult.SignatureFormat = string.Empty;
                throw;
            }
            finally
            {
                if (blob != 0 && !XadesHelper.XadesFreeVerificationInfoArray(blob))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg3 = $"Ошибка освобождения структуры XADES_VERIFICATION_INFO_ARRAY: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
                if (verifyPara.pXadesVerifyPara != 0)
                {
                    Marshal.FreeHGlobal(verifyPara.pXadesVerifyPara);
                }
            }

            return signatureValidationResult;
        }
    }
}
