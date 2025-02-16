using CryptStructure;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CryptoProWrapper
{
    public class LowLevelEncryptByDescrypt : IEncryptByDescrypt
    {
        const int CALG_AES_256 = 0x00006610;
        //private IntPtr hKey;
        private const uint CALG_SHA_512 = 0x8004;
        private const uint CRYPT_EXPORTABLE = 0x00000001; // Если нужно обеспечить возможность экспорта импортируемой ключевой пары впоследствии, то в параметре флаги необходимо передать значение CRYPT_EXPORTABLE

        [SecuritySafeCritical]
        public unsafe SignatureCreateResult GetEncrypt(CryptoContainer container, string content)
        {
            var signatureCreateResult = new SignatureCreateResult();
            nint hProv = 0;
            IntPtr hHash = IntPtr.Zero;
            IntPtr hKey = IntPtr.Zero;

            var password = "0000";
            try
            {
                if (!ADVAPI32Helper.CryptAcquireContext(
                    out hProv,
                    null,
                    null,
                    80,
                    Constants.CRYPT_VERIFYCONTEXT))
                {
                    var err = Kernel32Helper.GetLastError();
                    var error = (uint)Marshal.GetLastPInvokeError();
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера. Ошибка: {err}", CapiLiteCoreErrors.InternalServerError);
                }

                byte[] buffer = new byte[8];
                byte[] pbRandomData = new byte[8];



                if (!ADVAPI32Helper.CryptCreateHash(hProv, Constants.CALG_GR3411_2012_256, IntPtr.Zero, 0, ref hHash))
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription(err);
                    throw new Exception($"Error code: {err}, error description: {errDesc}");
                }

                var dwLength = (uint)(sizeof(char) * password.Length);
                if (!ADVAPI32Helper.CryptHashData(hHash, Encoding.UTF32.GetBytes(password), (int)dwLength, 0))
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription(err);
                    throw new Exception($"Error code: {err}, error description: {errDesc}");
                }

                if (!ADVAPI32Helper.CryptDeriveKey(hProv, Constants.CALG_G28147, hHash, Constants.CRYPT_EXPORTABLE, ref hKey))
                //if (ADVAPI32Helper.CryptGenKey(hProv, /*Constants.CALG_G28147*/Constants.CALG_G28147, CRYPT_EXPORTABLE, ref hKey))
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription(err);
                    throw new Exception($"Error code: {err}, error description: {errDesc}");
                }

                uint dwCount = 0;
                if (!ADVAPI32Helper.CryptGetKeyParam(hKey, Constants.KP_IV, null, ref dwCount, 0))
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription(err);
                    throw new Exception($"Error code: {err}, error description: {errDesc}");
                }

                pbRandomData = new byte[dwCount];

                if (!ADVAPI32Helper.CryptGenRandom(hProv, dwCount, pbRandomData))
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription(err);
                    throw new Exception($"Error code: {err}, error description: {errDesc}");
                }

                if (!ADVAPI32Helper.CryptSetKeyParam(hKey, Constants.KP_IV, pbRandomData, 0))
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription(err);
                    throw new Exception($"Error code: {err}, error description: {errDesc}");
                }

                string encryptedString = string.Empty;
                string result2 = string.Empty;
                dwLength = (uint)Encoding.UTF32.GetByteCount(content);
                buffer = new byte[dwLength];
                Encoding.UTF32.GetBytes(content, 0, content.Length, buffer, 0);
                if (ADVAPI32Helper.CryptEncrypt(hKey, IntPtr.Zero, true, 0, buffer, ref dwLength, dwLength))
                {
                    encryptedString = Encoding.UTF32.GetString(buffer);
                    signatureCreateResult.SignatureData = buffer;
                }
                else
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription(err);
                    throw new Exception($"Error code: {err}, error description: {errDesc}");
                }

                if (!ADVAPI32Helper.CryptSetKeyParam(hKey, Constants.KP_IV, pbRandomData, 0))
                {
                    var err = Kernel32Helper.GetLastError();
                    var errDesc = Crypt32Helper.GetErrorDescription((uint)err);
                }

                if (ADVAPI32Helper.CryptDecrypt(hKey, IntPtr.Zero, 1, 0, buffer, ref dwLength))
                {
                    string result = Encoding.UTF32.GetString(buffer);
                }
            }
            catch (CapiLiteCoreException ex)
            {
                signatureCreateResult.Error = ex.Message;
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка шифрования: {ex.Message}");
                signatureCreateResult.Error = "Ошибка получения подписи";
                throw;
            }
            finally
            {
                if (hProv != 0) ADVAPI32Helper.CryptReleaseContext(hProv, 0);
                if (hHash != IntPtr.Zero) ADVAPI32Helper.CryptDestroyHash(hHash);
                if (hKey != IntPtr.Zero) ADVAPI32Helper.CryptDestroyKey(hKey);
                Crypt32Helper.CryptMsgClose(hKey);
            }
            return signatureCreateResult;
        }

        [SecuritySafeCritical]
        public unsafe SignatureCreateResult GetDecrypt(CryptoContainer container, string content)
        {
            nint hProv = 0;
            IntPtr hKey = IntPtr.Zero;
            var signatureCreateResult = new SignatureCreateResult();
            var password = "xXx_password_xXx";
            try
            {
                uint dwFlags = Constants.CRYPT_SILENT;
                if (!ADVAPI32Helper.CryptAcquireContext(out hProv, container.Name, container.ProviderName, (uint)container.ProviderType, dwFlags))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера. Ошибка: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                IntPtr hHash = IntPtr.Zero;
                if (ADVAPI32Helper.CryptCreateHash(hProv, /*CALG_SHA_512*/Constants.CALG_GR3411_2012_256, IntPtr.Zero, 0, ref hHash))
                {
                    var dwLength = (uint)(sizeof(char) * password.Length);
                    if (ADVAPI32Helper.CryptHashData(hHash, Encoding.Unicode.GetBytes(password), (int)dwLength, 0))
                    {
                        if (ADVAPI32Helper.CryptDeriveKey(hProv, CALG_AES_256, hHash, CRYPT_EXPORTABLE, ref hKey))
                        {
                            dwLength = (uint)Encoding.Unicode.GetByteCount(content);
                            byte[] buffer = new byte[dwLength + 1024];
                            Encoding.Unicode.GetBytes(content, 0, content.Length, buffer, 0);
                            //if (ADVAPI32Helper.CryptEncrypt(hKey, IntPtr.Zero, true, 0, buffer, ref dwLength, dwLength + 1024))
                            //{
                            //    string encryptedString = BitConverter.ToString(buffer).Replace("-", string.Empty);
                            //}
                            if (ADVAPI32Helper.CryptDecrypt(hKey, IntPtr.Zero, 1, 0, buffer, ref dwLength))
                            {
                                string result = Encoding.Unicode.GetString(buffer);
                                //signatureCreateResult.SignatureData = buffer; = result.Replace("ЄЄ\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",
                                //      "");
                            }
                            ADVAPI32Helper.CryptDestroyKey(hKey);
                        }
                        ADVAPI32Helper.CryptDestroyHash(hHash);
                    }
                    ADVAPI32Helper.CryptReleaseContext(hProv, 0);
                }
            }
            catch (CapiLiteCoreException ex)
            {
                signatureCreateResult.Error = ex.Message;
                throw;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка дешифрования: {ex.Message}");
                signatureCreateResult.Error = "Ошибка получения подписи";
                throw;
            }
            finally
            {
                if (hProv != 0) ADVAPI32Helper.CryptReleaseContext(hProv, 0);
                Crypt32Helper.CryptMsgClose(hKey);
            }
            return signatureCreateResult;
        }

        [SecurityCritical]
        public unsafe SignatureCreateResult EncryptMessage(CryptoContainer container, string content)
        {
            var signatureCreateResult = new SignatureCreateResult();

            try
            {

            }
            catch (Exception ex)
            {
                signatureCreateResult.Error = ex.Message;
                throw;
            }
            finally
            {

            }

            return signatureCreateResult;
        }
    }
}
