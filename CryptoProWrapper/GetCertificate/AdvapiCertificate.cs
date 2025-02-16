using Crypto.Entities;
using Crypto.Helpers;
using Crypto.Interfaces;
using CryptStructure;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace CryptoProWrapper.GetCertificate
{
    public class AdvapiCertificate : IGetCertificate
    {
        public unsafe byte[]? GetCertificateFromContainer(CryptoContainer container)
        {
            nint hProv = 0;

            try
            {
                #region получение провайдера
                uint dwFlags = Constants.CRYPT_SILENT;
                //uint dwFlags = 0; // для проверки места расположения контейнера

                if (!ADVAPI32Helper.CryptAcquireContext(out hProv, container.Name, container.ProviderName, (uint)container.ProviderType, dwFlags))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера. Ошибка: {error.ErrorMessage}; код ошибки {error.LastErrorCode}. Имя контейнера : {container.Name}", CapiLiteCoreErrors.InternalServerError);
                }
                #endregion

                return GetCertificateByCryptAcquireContext(hProv);
            }
            catch (CapiLiteCoreException ex)
            {
                var err = ExceptionHelper.GetLastPInvokeError();
                string logMsg = $"Ошибка получения сертификата: {err.ErrorMessage}";
                throw;
            }
            catch (Exception ex)
            {
                var err = ExceptionHelper.GetLastPInvokeError();
                string logMsg = $"Ошибка получения сертификата: {err.ErrorMessage}";
                throw;
            }
            finally
            {
                if (hProv != 0 && !ADVAPI32Helper.CryptReleaseContext(hProv, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg = $"Ошибка освобождения контекста провайдера: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }
        }

        public unsafe byte[]? GetCertificateByCryptAcquireContext(nint hProv)
        {
            byte[]? dCert = null;
            nint phUserKey = 0;

            try
            {
                #region получение ключа
                string logMsg = $"Вызов метода CryptGetUserKey";

                if (!ADVAPI32Helper.CryptGetUserKey(hProv, Constants.AT_KEYEXCHANGE, out phUserKey))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg1 = $"Не удалось получить дескриптор ключа пользователя. Ошибка: {error.ErrorMessage}; код ошибки {error.LastErrorCode}";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор ключа пользователя. Ошибка: {error.ErrorMessage}; код ошибки {error.LastErrorCode}", CapiLiteCoreErrors.InternalServerError);
                }
                #endregion

                #region получение сертификата
                uint dt_len = 0;
                string logMsg2 = $"Первичный вызов метода CryptGetKeyParam";
                ADVAPI32Helper.CryptGetKeyParam(phUserKey, Constants.KP_CERTIFICATE, null, ref dt_len, 0);
                dCert = new byte[dt_len];
                string logMsg3 = $"Вторичный вызов метода CryptGetKeyParam с параметрами: dt_len = {dt_len}";
                ADVAPI32Helper.CryptGetKeyParam(phUserKey, Constants.KP_CERTIFICATE, dCert, ref dt_len, 0);
                #endregion
            }
            catch(Exception ex)
            {
                string logMsg4 = ex.Message;
            }
            finally
            {
                if (phUserKey != 0 && !ADVAPI32Helper.CryptDestroyKey(phUserKey))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg5 = $"Ошибка освобождения дескриптора пар открытого и закрытого ключа: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }

            return dCert;
        }

        public X509Certificate GetCertificateFromPfx(string path)
        {
            throw new NotImplementedException();
        }

        public unsafe ICCertificate? GetCertFromCadesSignature(byte[] signarureData)
        {
            nint hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0U, 0, 0, 0, 0);
            nint hInfo = 0;
            nint hCertStore = 0;

            if (hMsg == 0)
            {
                var error = ExceptionHelper.GetLastPInvokeError();
                throw new CapiLiteCoreException($"Ошибка открытия криптографического сообщения для декодирования подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
            }

            try
            {
                fixed (byte* pSignMessage = signarureData)
                {
                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSignMessage, (uint)signarureData.Length, true))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        throw new CapiLiteCoreException($"Ошибка загрузки подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                hCertStore = Crypt32Helper.CertOpenStore(Constants.CERT_STORE_PROV_MSG, 0, 0, 0, hMsg);
                var store = new CStore(hCertStore);
                var certs = store.GetCertificates();
                var signerCert = certs.FirstOrDefault();
                return signerCert;
            }
            catch (Exception err)
            {
                string logMsg1 = err.Message;
            }
            finally
            {
                if (hMsg != 0 && !Crypt32Helper.CryptMsgClose(hMsg))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg2 = $"Ошибка освобождения контекста дескриптора сообщения: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }

                Crypt32Helper.CertCloseStore(hCertStore, Constants.CERT_CLOSE_STORE_FORCE_FLAG);
                if (hInfo != IntPtr.Zero) Marshal.FreeHGlobal(hInfo);
            }

            return null;
        }

        public unsafe ICCertificate? GetCertFromXadesSignature(byte[] signarureData)
        {
            var xDoc = new XmlDocument();
            MemoryStream ms = new MemoryStream(signarureData);
            xDoc.Load(ms);

            XmlNamespaceManager nsmgr = new XmlNamespaceManager(xDoc.NameTable);
            nsmgr.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");
            //string xpath = "//ds:X509Certificate";

            var item = xDoc.SelectSingleNode("//ds:X509Certificate[1]", nsmgr);
            string? certBase64Str = item?.FirstChild?.Value;

            if (certBase64Str == null)
            {
                return null;
            }

            var certBytes = Convert.FromBase64String(certBase64Str);
            var cert = new CCertificate(certBytes);

            return cert;
        }

        public unsafe string GetCertSerialNumberFromSignature(byte[] signarureData)
        {
            nint hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0U, 0, 0, 0, 0);
            nint hInfo = 0;
            string serialNumber = string.Empty;

            if (hMsg == 0)
            {
                var error = ExceptionHelper.GetLastPInvokeError();
                throw new CapiLiteCoreException($"Ошибка открытия криптографического сообщения для декодирования подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
            }

            try
            {
                fixed (byte* pSignMessage = signarureData)
                {
                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSignMessage, (uint)signarureData.Length, true))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        throw new CapiLiteCoreException($"Ошибка загрузки подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                uint signerIndex = 0;
                var signerInfoSize = 0;

                if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, signerIndex, 0, ref signerInfoSize))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }
                hInfo = Marshal.AllocHGlobal((int)signerInfoSize);
                if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, signerIndex, hInfo, ref signerInfoSize))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }
                CMSG_SIGNER_INFO? pSignerInfo = (CMSG_SIGNER_INFO?)Marshal.PtrToStructure(hInfo, typeof(CMSG_SIGNER_INFO));

                if (pSignerInfo.HasValue)
                {
                    var serialNumberBytes = new byte[pSignerInfo.Value.SerialNumber.cbData];
                    Marshal.Copy(pSignerInfo.Value.SerialNumber.pbData, serialNumberBytes, 0, (int)pSignerInfo.Value.SerialNumber.cbData);
                    Array.Reverse<byte>(serialNumberBytes);
                    serialNumber = PivotFunctionsHelper.ToHexString(serialNumberBytes);
                }
            }
            catch (Exception err)
            {
                string logMsg1 = err.Message;
            }
            finally
            {
                if (hMsg != 0 && !Crypt32Helper.CryptMsgClose(hMsg))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg2 = $"Ошибка освобождения контекста дескриптора сообщения: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }

                if (hInfo != IntPtr.Zero) Marshal.FreeHGlobal(hInfo);
            }

            return serialNumber;
        }
    }
}
