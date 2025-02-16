using CryptoProWrapper.SignatureVerification;
using CryptStructure;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CryptoProWrapper
{
    public class CadesSignatureVerification : IValidateCadesSignature
    {

        public SignatureValidationResult VerifySignature(byte[] signMessage, byte[]? data, CadesFormat signatureFormat)
        {
            var result = new SignatureValidationResult();
            nint blob = 0;
            nint verInfo = 0;
            var pVerifyPara = new CADES_VERIFY_MESSAGE_PARA();

            try
            {
                var pVerifyMessagePara = new CRYPT_VERIFY_MESSAGE_PARA();
                var pCadesVerifyPara = new CADES_VERIFICATION_PARA();
                pVerifyMessagePara.cbSize = (uint)Marshal.SizeOf(typeof(CRYPT_VERIFY_MESSAGE_PARA));
                pCadesVerifyPara.dwSize = (uint)Marshal.SizeOf(typeof(CADES_VERIFICATION_PARA));
                pCadesVerifyPara.dwCadesType = 0x00000001;
                pVerifyMessagePara.dwMsgAndCertEncodingType = Constants.PKCS_7_OR_X509_ASN_ENCODING;
                pVerifyPara.pVerifyMessagePara = Marshal.AllocHGlobal((int)pVerifyMessagePara.cbSize);
                Marshal.StructureToPtr(pVerifyMessagePara, pVerifyPara.pVerifyMessagePara, true);
                pVerifyPara.pCadesVerifyPara = Marshal.AllocHGlobal((int)pCadesVerifyPara.dwSize);
                Marshal.StructureToPtr(pCadesVerifyPara, pVerifyPara.pCadesVerifyPara, true);
                pVerifyPara.dwSize = (uint)Marshal.SizeOf(typeof(CADES_VERIFY_MESSAGE_PARA));
                uint dwSignerIndex = 0;
                var r = CadesHelper.CadesVerifyMessage(
                    ref pVerifyPara,
                    dwSignerIndex,
                    signMessage,
                    (uint)signMessage.Length,
                    ref blob,
                    ref verInfo
                );

                var strVerInfo = Marshal.PtrToStructure(verInfo, typeof(CADES_VERIFICATION_INFO));
                var strBlob = Marshal.PtrToStructure(blob, typeof(CRYPT_DATA_BLOB));

                if (strBlob is CRYPT_DATA_BLOB strBlobStruct)
                {
                    byte[] arr = new byte[strBlobStruct.cbData];
                    Marshal.Copy(strBlobStruct.pbData, arr, 0, strBlobStruct.cbData);
                    //var str = Encoding.Default.GetString(arr);
                }

                if (strVerInfo is CADES_VERIFICATION_INFO verInfoStruct)
                {
                    var certContextPtr = Marshal.PtrToStructure(verInfoStruct.pSignerCert, typeof(CERT_CONTEXT));
                    var cert1 = new X509Certificate2(verInfoStruct.pSignerCert);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                throw;
            }
            finally
            {
                if (blob != 0) CadesHelper.CadesFreeBlob(blob);
                if (verInfo != 0) CadesHelper.CadesFreeVerificationInfo(verInfo);
                if (pVerifyPara.pVerifyMessagePara != 0)
                {
                    Marshal.FreeHGlobal(pVerifyPara.pVerifyMessagePara);
                }
                if (pVerifyPara.pCadesVerifyPara != 0)
                {
                    Marshal.FreeHGlobal(pVerifyPara.pCadesVerifyPara);
                }
            }

            result.Error = "Ошибка проверки подписи";
            return result;
        }
    }
}
