using Crypto.Entities;
using Crypto.Pivot;
using CryptoAPI.Services;
using CryptStructure;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CryptoProWrapper.GetSignature
{
    public unsafe class SimplifiedEncryptMessage : IEncryptionMessageService
    {
        private const uint numOfCerts = 1;

        [SecuritySafeCritical]
        public EncryptionResult EncryptMessage(CryptoContainer container, byte[] content, string encryptionAlgorythmOid)
        {
            nint hProv = 0;
            string logMsg = $"Начало EncryptMessage";

            var encryptionResult = new EncryptionResult();
            try
            {
                #region encrypting
                uint dwFlags = Constants.CRYPT_SILENT;
                string logMsg3 = $"Вызов метода CryptAcquireContext с параметрами: container.Name = {container.Name}; container.ProviderName = {container.ProviderName}; container.ProviderType = {container.ProviderType}";

                if (!ADVAPI32Helper.CryptAcquireContext(out hProv, container.Name, container.ProviderName, (uint)container.ProviderType, dwFlags))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg4 = $"Не удалось получить дескриптор провайдера. {error.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера. {error.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                nint phUserKey;
                string logMsg5 = $"Вызов метода CryptGetUserKey";

                if (!ADVAPI32Helper.CryptGetUserKey(hProv, Constants.AT_KEYEXCHANGE, out phUserKey))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg6 = $"Не удалось получить дескриптор ключа пользователя. {error.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор ключа пользователя. {error.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                byte[] dCert;
                uint dt_len = 0;
                string logMsg7 = $"Вызов метода CryptGetKeyParam";
                ADVAPI32Helper.CryptGetKeyParam(phUserKey, Constants.KP_CERTIFICATE, null, ref dt_len, 0);
                dCert = new byte[dt_len];
                string logMsg8 = $"Повторный вызов метода CryptGetKeyParam с параметрами: dt_len = {dt_len}";
                ADVAPI32Helper.CryptGetKeyParam(phUserKey, Constants.KP_CERTIFICATE, dCert, ref dt_len, 0);
                var cert = new CCertificate(dCert);
                var messagePara = new CRYPT_ENCRYPT_MESSAGE_PARA();
                messagePara.cbSize = (uint)Marshal.SizeOf(typeof(CRYPT_ENCRYPT_MESSAGE_PARA));
                messagePara.hCryptProv = hProv;
                messagePara.dwMsgEncodingType = Constants.PKCS_7_OR_X509_ASN_ENCODING;
                var digestOidLength = Encoding.ASCII.GetByteCount(encryptionAlgorythmOid);
                var digestOidRaw = stackalloc byte[digestOidLength + 1];
                Encoding.ASCII.GetBytes(encryptionAlgorythmOid, new Span<byte>(digestOidRaw, digestOidLength));
                messagePara.ContentEncryptionAlgorithm.pszObjId = (nint)digestOidRaw;
                nint pEncryptPara = Marshal.AllocHGlobal(Marshal.SizeOf(messagePara));
                byte[] pbEncryptedBlob;
                uint pcbEncryptedBlob = 0;

                try
                {
                    Marshal.StructureToPtr(messagePara, pEncryptPara, false);
                    IntPtr[] rgpRecipientCert = new IntPtr[numOfCerts];
                    rgpRecipientCert[0] = cert.handle;
                    string logMsg9 = $"Вызов метода CryptEncryptMessage с параметрами: encryptionAlgorythmOid = {encryptionAlgorythmOid}";

                    if (!Crypt32Helper.CryptEncryptMessage(
                        pEncryptPara,
                        numOfCerts,
                        rgpRecipientCert,
                        content,
                        (uint)content.Length,
                        null,
                        ref pcbEncryptedBlob
                    ))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        bool accessDenied = error.ErrorMessage.ToLower().Contains("access denied");

                        if (accessDenied && cert != null && cert.isPrivateKeyExpired)
                        {
                            error.ErrorMessage = $"{error.ErrorMessage} Возможная причина: истек срок действия закрытого ключа.";
                        }

                        string logMsg10 = $"Не удалось зашифровать сообщение. {error.ErrorMessage}.";
                        throw new CapiLiteCoreException($"Не удалось зашифровать сообщение. {error.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                    }

                    pbEncryptedBlob = new byte[pcbEncryptedBlob];
                    string logMsg11 = $"Повторный вызов метода CryptEncryptMessage с параметрами: encryptionAlgorythmOid = {encryptionAlgorythmOid}, pcbEncryptedBlob = {pcbEncryptedBlob}";

                    if (!Crypt32Helper.CryptEncryptMessage(
                        pEncryptPara,
                        numOfCerts,
                        rgpRecipientCert,
                        content,
                        (uint)content.Length,
                        pbEncryptedBlob,
                        ref pcbEncryptedBlob
                    ))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        bool accessDenied = error.ErrorMessage.ToLower().Contains("access denied");

                        if (accessDenied && cert != null && cert.isPrivateKeyExpired)
                        {
                            error.ErrorMessage = $"{error.ErrorMessage} Возможная причина: истек срок действия закрытого ключа.";
                        }

                        string logMsg12 = $"Не удалось зашифровать сообщение. {error.ErrorMessage}.";
                        throw new CapiLiteCoreException($"Не удалось зашифровать сообщение. {error.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                    }
                }
                catch(CapiLiteCoreException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    string logMsg13 = $"Ошибка проверки подписи: {ex.Message}";
                    throw;
                }
                finally
                {
                    if (pEncryptPara != 0) Marshal.FreeHGlobal(pEncryptPara);
                }
                #endregion

                encryptionResult.EncryptedData = pbEncryptedBlob;
                encryptionResult.Success = true;
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg2 = ex.Message;
                throw;
            }
            finally
            {
                if (hProv != 0 && !ADVAPI32Helper.CryptReleaseContext(hProv, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg14 = $"Ошибка освобождения контекста провайдера: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }
            return encryptionResult;
        }

        [SecuritySafeCritical]
        public DecryptionResult DecryptMessage(CryptoContainer container, byte[] content)
        {
            nint hProv = 0;
            string logMsg1 = $"Начало DecryptMessage";
            var decryptionResult = new DecryptionResult();

            try
            {
                uint dwFlags = Constants.CRYPT_SILENT;
                string logMsg2 = $"Вызов метода CryptAcquireContext с параметрами: container.Name = {container.Name}; container.ProviderName = {container.ProviderName}; container.ProviderType = {container.ProviderType}";

                if (!ADVAPI32Helper.CryptAcquireContext(out hProv, container.Name, container.ProviderName, (uint)container.ProviderType, dwFlags))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg3 = $"Не удалось получить дескриптор провайдера. {err.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера. {err.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                var asciiPinLength = Encoding.ASCII.GetByteCount(container.Pin);
                var asciiPin = stackalloc byte[asciiPinLength + 1];
                Encoding.ASCII.GetBytes(container.Pin, new Span<byte>(asciiPin, asciiPinLength));
                string logMsg4 = $"Вызов метода CryptSetProvParam";

                if (!ADVAPI32Helper.CryptSetProvParam(hProv, Constants.PP_KEYEXCHANGE_PIN, (nint)asciiPin, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg5 = $"Не удалось установить пин контейнера. {err.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось установить пин контейнера. {err.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                nint phUserKey;
                string logMsg6 = $"Вызов метода CryptGetUserKey";

                if (!ADVAPI32Helper.CryptGetUserKey(hProv, Constants.AT_KEYEXCHANGE, out phUserKey))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg7 = $"Не удалось получить дескриптор ключа пользователя. {err.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор ключа пользователя. {err.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                byte[] dCert;

                uint dt_len = 0;
                string logMsg8 = $"Вызов метода CryptGetKeyParam";
                ADVAPI32Helper.CryptGetKeyParam(phUserKey, Constants.KP_CERTIFICATE, null, ref dt_len, 0);
                dCert = new byte[dt_len];
                string logMsg9 = $"Повторный вызов метода CryptGetKeyParam с параметрами: dt_len = {dt_len}";
                ADVAPI32Helper.CryptGetKeyParam(phUserKey, Constants.KP_CERTIFICATE, dCert, ref dt_len, 0);

                using var cert = new CCertificate(dCert);
                cert.SetProvider(container.Name, string.Empty);

                #region decrypting
                using var s = new CStore();
                s.Open(StoreType.Memory);
                s.Add(cert);

                var pinnedStoreHandle = GCHandle.Alloc(s.handle, GCHandleType.Pinned);
                var decryptPara = new CRYPT_DECRYPT_MESSAGE_PARA();
                decryptPara.cbSize = (uint)Marshal.SizeOf(typeof(CRYPT_DECRYPT_MESSAGE_PARA));
                decryptPara.dwMsgAndCertEncodingType = Constants.PKCS_7_OR_X509_ASN_ENCODING;
                decryptPara.cCertStore = 1;
                decryptPara.rghCertStore = pinnedStoreHandle.AddrOfPinnedObject();
                decryptPara.dwFlags = Constants.CRYPT_SILENT;
                var cbEncryptedBlob = (uint)content.Length;
                byte[] pbDecrypted;
                uint pcbDecrypted = 0;
                IntPtr ppXchgCert = IntPtr.Zero;
                string logMsg12 = $"Вызов метода CryptEncryptMessage";

                if (!Crypt32Helper.CryptDecryptMessage(
                    ref decryptPara,
                    content,
                    cbEncryptedBlob,
                    null,
                    ref pcbDecrypted,
                    ppXchgCert
                ))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    bool accessDenied = err.ErrorMessage.ToLower().Contains("access denied");

                    if (accessDenied && cert != null && cert.isPrivateKeyExpired)
                    {
                        err.ErrorMessage = $"{err.ErrorMessage} Возможная причина: истек срок действия закрытого ключа.";
                    }

                    string logMsg13 = $"Не удалось расшифровать сообщение. {err.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось расшифровать сообщение. {err.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                pbDecrypted = new byte[pcbDecrypted];
                string logMsg14 = $"Повторный вызов метода CryptEncryptMessage с параметрами: pcbDecrypted = {pcbDecrypted}";

                if (!Crypt32Helper.CryptDecryptMessage(
                    ref decryptPara,
                    content,
                    cbEncryptedBlob,
                    pbDecrypted,
                    ref pcbDecrypted,
                    ppXchgCert
                ))
                {                    
                    var err = ExceptionHelper.GetLastPInvokeError();
                    bool accessDenied = err.ErrorMessage.ToLower().Contains("access denied");

                    if (accessDenied && cert != null && cert.isPrivateKeyExpired)
                    {
                        err.ErrorMessage = $"{err.ErrorMessage} Возможная причина: истек срок действия закрытого ключа.";
                    }

                    string logMsg15 = $"Не удалось расшифровать сообщение. {err.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось расшифровать сообщение. {err.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                string result = Convert.ToBase64String(pbDecrypted);
                decryptionResult.Content = result;
                decryptionResult.Success = true;
                #endregion
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg10 = ex.Message;
                throw;
            }
            finally
            {
                if (hProv != 0 && !ADVAPI32Helper.CryptReleaseContext(hProv, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg11 = $"Ошибка освобождения контекста провайдера: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }
            return decryptionResult;
        }
    }
}