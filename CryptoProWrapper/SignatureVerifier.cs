using CryptoProWrapper;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptoAPI
{
    public class SignatureVerifier
    {
        public const int X509_ASN_ENCODING = 0x00000001;
        public const int PKCS_7_ASN_ENCODING = 0x00010000;

        static string GetErrorDescription(uint errorCode)
        {
            //string messageBuffer;
            StringBuilder messageBuffer = new StringBuilder(256);
            uint result = Kernel32Helper.FormatMessage(
                0x00001000 | 0x00000200 | 0x00000100,
                IntPtr.Zero,
                errorCode,
                0x0419,//0x0409, // English (United States) language
                out messageBuffer,
                0,
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

        public void VerifyMsgCapiLite()
        {
            byte[] pbSignedBlob = File.ReadAllBytes("C:\\Users\\1\\Downloads\\file_signed.p7s");
            uint dwSignerIndex = 0;
            byte[] pbDecoded = new byte[0];

            CryptStructure.CRYPT_VERIFY_MESSAGE_PARA verifyPara = new CryptStructure.CRYPT_VERIFY_MESSAGE_PARA();
            verifyPara.cbSize = (uint)Marshal.SizeOf(typeof(CryptStructure.CRYPT_VERIFY_MESSAGE_PARA));
            verifyPara.hCryptProv = 0;
            verifyPara.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
            verifyPara.pfnGetSignerCertificate = IntPtr.Zero;
            verifyPara.pvGetArg = IntPtr.Zero;
            var pvGetArg = IntPtr.Zero;
            verifyPara.pvGetArg = pvGetArg;
            IntPtr certContext = IntPtr.Zero;
            GCHandle pCertContext;

            Byte[] pbDecodedMessageBlob = new byte[4096];
            uint cbDecodedMessageBlob = 0;

            pCertContext = GCHandle.Alloc(IntPtr.Zero, GCHandleType.Pinned);
            var r = Crypt32Helper.CryptVerifyMessageSignature(
                ref verifyPara,
                dwSignerIndex,
                pbSignedBlob,
                (uint)pbSignedBlob.Length,
                pbDecodedMessageBlob,
                ref cbDecodedMessageBlob,
                pCertContext.AddrOfPinnedObject()
            );
            pbDecodedMessageBlob = new Byte[cbDecodedMessageBlob];
            var verificationResult = Crypt32Helper.CryptVerifyMessageSignature(
                ref verifyPara,
                dwSignerIndex,
                pbSignedBlob,
                (uint)pbSignedBlob.Length,
                pbDecodedMessageBlob,
                ref cbDecodedMessageBlob,
                pCertContext.AddrOfPinnedObject()
            );
            //var c = new X509Certificate2(((IntPtr)pCertContext.Target));
            var e1 = Kernel32Helper.GetLastError();
            Console.WriteLine(GetErrorDescription(e1));
            if (e1 != 0 || !verificationResult)
            {
                Console.WriteLine("Подпись не была проверена");
                var e = Marshal.GetLastPInvokeError();
            }
            else
            {
                Console.WriteLine(System.Text.Encoding.Default.GetString(pbDecodedMessageBlob));
            }
        }

        public void VerifyCadesMsg()
        {
            IntPtr blob = IntPtr.Zero;
            IntPtr verInfo = IntPtr.Zero;
            var pVerifyPara = new CryptStructure.CADES_VERIFY_MESSAGE_PARA();

            try
            {
                var store = new X509Store();
                store.Open(OpenFlags.ReadOnly);
                var cert = store.Certificates[2];
                CryptStructure.CRYPT_VERIFY_MESSAGE_PARA pVerifyMessagePara = new CryptStructure.CRYPT_VERIFY_MESSAGE_PARA();
                CryptStructure.CADES_VERIFICATION_PARA pCadesVerifyPara = new CryptStructure.CADES_VERIFICATION_PARA();
                pVerifyMessagePara.cbSize = (uint)Marshal.SizeOf(typeof(CryptStructure.CRYPT_VERIFY_MESSAGE_PARA));
                pCadesVerifyPara.dwSize = (uint)Marshal.SizeOf(typeof(CryptStructure.CADES_VERIFICATION_PARA));
                pCadesVerifyPara.dwCadesType = 0x00000001;
                pVerifyMessagePara.dwMsgAndCertEncodingType = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING;
                pVerifyPara.pVerifyMessagePara = Marshal.AllocHGlobal((int)pVerifyMessagePara.cbSize);
                Marshal.StructureToPtr(pVerifyMessagePara, pVerifyPara.pVerifyMessagePara, true);
                pVerifyPara.pCadesVerifyPara = Marshal.AllocHGlobal((int)pCadesVerifyPara.dwSize);
                Marshal.StructureToPtr(pCadesVerifyPara, pVerifyPara.pCadesVerifyPara, true);
                byte[] pbSignedBlob = File.ReadAllBytes("C:\\Users\\1\\Downloads\\signed_cades_file");
                pVerifyPara.dwSize = (uint)Marshal.SizeOf(typeof(CryptStructure.CADES_VERIFY_MESSAGE_PARA));

                uint dwSignerIndex = 0;
                var r = CadesHelper.CadesVerifyMessage(
                    ref pVerifyPara,
                    dwSignerIndex,
                    pbSignedBlob,
                    (uint)pbSignedBlob.Length,
                    ref blob,
                    ref verInfo
                );

                var strVerInfo = Marshal.PtrToStructure(verInfo, typeof(CryptStructure.CADES_VERIFICATION_INFO));
                var strBlob = Marshal.PtrToStructure(blob, typeof(CryptStructure.CRYPT_DATA_BLOB));

                if (strBlob is CryptStructure.CRYPT_DATA_BLOB strBlobStruct)
                {
                    byte[] arr = new byte[strBlobStruct.cbData];
                    Marshal.Copy(strBlobStruct.pbData, arr, 0, strBlobStruct.cbData);
                    var str = System.Text.Encoding.Default.GetString(arr);
                    Console.WriteLine(str);
                }

                if (strVerInfo is CryptStructure.CADES_VERIFICATION_INFO verInfoStruct)
                {
                    var certContextPtr = Marshal.PtrToStructure(verInfoStruct.pSignerCert, typeof(CryptStructure.CERT_CONTEXT));
                    var cert1 = new X509Certificate2(verInfoStruct.pSignerCert);

                    Console.WriteLine(cert1.SubjectName);
                }

                var err = Kernel32Helper.GetLastError();
                Console.WriteLine(GetErrorDescription(err));
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                CadesHelper.CadesFreeBlob(blob);
                CadesHelper.CadesFreeVerificationInfo(verInfo);
                if (pVerifyPara.pVerifyMessagePara != 0)
                {
                    Marshal.FreeHGlobal(pVerifyPara.pVerifyMessagePara);
                }
                if (pVerifyPara.pCadesVerifyPara != 0)
                {
                    Marshal.FreeHGlobal(pVerifyPara.pCadesVerifyPara);
                }
            }
        }
    }
}
