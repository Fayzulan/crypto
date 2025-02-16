using CryptoProWrapper.SignatureVerification;
using CryptStructure;
using System.Runtime.InteropServices;

namespace CryptoProWrapper
{
    public class CryptSignatureVerification : IValidateCadesSignature
    {
        public SignatureValidationResult VerifySignature(byte[] signMessage, byte[]? data, CadesFormat signatureFormat)
        {
            var result = new SignatureValidationResult();
            GCHandle pCertContext = GCHandle.Alloc(IntPtr.Zero, GCHandleType.Pinned);

            try
            {
                uint dwSignerIndex = 0;
                var verifyPara = new CRYPT_VERIFY_MESSAGE_PARA();
                verifyPara.cbSize = (uint)Marshal.SizeOf(verifyPara);
                verifyPara.hCryptProv = 0;
                verifyPara.dwMsgAndCertEncodingType = Constants.PKCS_7_OR_X509_ASN_ENCODING;
                verifyPara.pfnGetSignerCertificate = IntPtr.Zero;
                verifyPara.pvGetArg = 0;
                uint cbDecodedMessageBlob = 0;
                pCertContext = GCHandle.Alloc(IntPtr.Zero, GCHandleType.Pinned);

                if (!Crypt32Helper.CryptVerifyMessageSignature(ref verifyPara, dwSignerIndex, signMessage, (uint)signMessage.Length, null,
                    ref cbDecodedMessageBlob, pCertContext.AddrOfPinnedObject()
                ))
                {
                    string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                    string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                    throw new CapiLiteCoreException($"Ошибка проверки подписи: {PInvokeError}; {Kernel32Error}", CapiLiteCoreErrors.InternalServerError);
                }

                //byte[] pbDecodedMessageBlob = new byte[cbDecodedMessageBlob];

                //if (!Crypt32Helper.CryptVerifyMessageSignature(ref verifyPara, dwSignerIndex, signMessage, (uint)signMessage.Length, pbDecodedMessageBlob,
                //    ref cbDecodedMessageBlob, pCertContext.AddrOfPinnedObject()
                //))
                //{
                //    string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                //    string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //    throw new CapiLiteCoreException($"Ошибка проверки подписи: {PInvokeError}; {Kernel32Error}");
                //}
                result.IsSignatureValid = cbDecodedMessageBlob > 0;
                result.Error = cbDecodedMessageBlob > 0 ? string.Empty : "Подпись не верна";
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                throw;
            }
            finally
            {
                // Очищаем ссылки и закрываем хранилище
                if (pCertContext.IsAllocated) pCertContext.Free();
            }

            return result;
        }
    }
}
