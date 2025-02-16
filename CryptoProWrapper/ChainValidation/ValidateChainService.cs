using CryptoProWrapper;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;

namespace CryptoAPI
{
    public class ValidateChainService
    {
        private IChainBuilder _chainBuilder;

        public ValidateChainService(IChainBuilder chainBuilder)
        {
            _chainBuilder = chainBuilder;
        }

        public ValidationResult ValidateChain(X509Certificate certificate, ChainValidationParameters chainValidationParameters)
        {
            var result = new ValidationResult();
            IntPtr chainContextPtr = IntPtr.Zero;
            try
            {
                chainContextPtr = _chainBuilder.Build(certificate.Handle, chainValidationParameters);
                if (chainContextPtr == IntPtr.Zero)
                {
                    result.errorCode = (int)ExceptionHelper.GetLastPInvokeError().LastErrorCode;
                    result.isValidated = false;
                    result.validationSucceed = false;
                    result.message = "Could not build the chain.";
                }
                int policyStatusError = 0;
                result.isValidated = Validate(chainContextPtr, out policyStatusError);

                if (result.isValidated)
                {
                    if (policyStatusError == 0)
                    {
                        return result;
                    }
                    else
                    {
                        var ans = GetErrorDescription((uint)policyStatusError);
                        Console.WriteLine($"Цепочка невалидна. \nДетали:\n{ans}");
                        result.message = ans;
                        result.validationSucceed = false;
                        result.errorCode = policyStatusError;
                        return result;
                    }

                }
                else
                {
                    result.isValidated = false;
                }
                return result;
            }
            catch (Exception E)
            {
                result.message = E.Message;
                return result;
            }
            finally
            {
                if (chainContextPtr != IntPtr.Zero)
                {
                    Crypt32Helper.CertFreeCertificateChain(chainContextPtr);
                }
            }
        }

        private bool Validate(IntPtr chainContext, out int policyStatusError)
        {
            try
            {
                if (chainContext == IntPtr.Zero)
                {
                    policyStatusError = 0;
                    return false;
                }
                else
                {
                    const int CERT_CHAIN_POLICY_SIGNING_FLAG = 1;

                    CryptStructure.CERT_CHAIN_POLICY_PARA policyPara = new CryptStructure.CERT_CHAIN_POLICY_PARA();
                    policyPara.cbSize = Marshal.SizeOf(typeof(CryptStructure.CERT_CHAIN_POLICY_PARA));
                    CryptStructure.CERT_CHAIN_POLICY_STATUS policyStatus = new CryptStructure.CERT_CHAIN_POLICY_STATUS();
                    policyStatus.cbSize = Marshal.SizeOf(typeof(CryptStructure.CERT_CHAIN_POLICY_STATUS));

                    bool verificationResult = Crypt32Helper.CertVerifyCertificateChainPolicy(
                        (IntPtr)CERT_CHAIN_POLICY_SIGNING_FLAG,
                        chainContext,
                        ref policyPara,
                        ref policyStatus
                    );
                    policyStatusError = policyStatus.dwError;
                    return true;
                }
            }
            catch (Exception Ex)
            {
                Console.WriteLine(Ex.Message);
                policyStatusError = 0;
                return false;
            }
        }

        static string GetErrorDescription(uint errorCode)
        {
            string messageBuffer;
            uint result = Kernel32Helper.FormatMessageC(
                0x00001000 | 0x00000200 | 0x00000100,
                IntPtr.Zero,
                errorCode,
                0x0409, // English (United States) language
                out messageBuffer,
                0,
                IntPtr.Zero);

            if (result == 0)
            {
                return "Failed to retrieve error description";
            }
            else
            {
                return messageBuffer.Trim();
            }
        }
    }
}
