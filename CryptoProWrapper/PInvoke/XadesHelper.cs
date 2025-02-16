using CryptStructure;
using System.Runtime.InteropServices;

namespace CryptoProWrapper
{
    public class XadesHelper
    {
        /// <summary>
        /// Функция для создания подписанного сообщения (XML документа) с возможностью задать параметры создания усовершенствованной подписи.
        /// </summary>
        /// <param name="pSignPara"></param>
        /// <param name="pXPathString"></param>
        /// <param name="fDetachedSignature"></param>
        /// <param name="pbToBeSigned"></param>
        /// <param name="cbToBeSigned"></param>
        /// <param name="ppSignedBlob"></param>
        /// <returns></returns>
        [DllImport(OSHelper.Xades, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool XadesSign(
           ref XADES_SIGN_MESSAGE_PARA pSignPara,
           nint pXPathString,
           bool fDetachedSignature,
           byte[] pbToBeSigned,
           uint cbToBeSigned,
           ref IntPtr ppSignedBlob // CRYPT_DATA_BLOB
        );

        [DllImport(OSHelper.Xades, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool XadesFreeBlob(IntPtr pBlob); // CRYPT_DATA_BLOB

        [DllImport(OSHelper.Xades, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool XadesFreeVerificationInfoArray(
            IntPtr pVerificationInfoArray // XADES_VERIFICATION_INFO_ARRAY
        );

        [DllImport(OSHelper.Xades, CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool XadesVerify(
           ref XADES_VERIFY_MESSAGE_PARA pVerifyPara,
           string? pXPathString, // LPCSTR
           byte[] pbSignedBlob,
           uint cbSignedBlob,
           ref IntPtr ppVerificationInfoArray // XADES_VERIFICATION_INFO_ARRAY
        );
    }
}
