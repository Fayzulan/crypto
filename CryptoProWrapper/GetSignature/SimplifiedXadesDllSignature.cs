using Crypto.Entities;
using CryptStructure;
using Microsoft.Extensions.Configuration;
using System.Runtime.InteropServices;
using System.Text;

namespace CryptoProWrapper.GetSignature
{
    public unsafe class SimplifiedXadesDllSignature : IGetXadesSignature
    {
        private readonly string TSPAddress;
        private IGetCertificate _getCert;

        public SimplifiedXadesDllSignature(
            IConfiguration configuration,
            IGetCertificate getCert)
        {
            _getCert = getCert;
            string? tspA = "адрес TSP сервера";

            if (!string.IsNullOrEmpty(tspA))
            {
                TSPAddress = tspA;
            }
        }

        public SignatureCreateResult GetXadesSignature(CryptoContainer container, byte[] data, XadesType xadesType, XadesFormat signatureFormat)
        {
            nint hProv = 0;
            var signatureCreateResult = new SignatureCreateResult();
            byte[]? signMessage = null;
            nint blob = 0;
            string logMsg1 = $"Начало GetXadesSignature";
            var signPara = new XADES_SIGN_MESSAGE_PARA();

            try
            {
                #region получение контекста провайдера
                uint dwFlags = Constants.CRYPT_SILENT;
                string logMsg2 = $"Вызов метода CryptAcquireContext с параметрами: container.Name = {container.Name}; container.ProviderName = {container.ProviderName}; container.ProviderType = {container.ProviderType}";

                if (!ADVAPI32Helper.CryptAcquireContext(out hProv, container.Name, container.ProviderName, (uint)container.ProviderType, dwFlags))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg3 = $"Не удалось получить дескриптор провайдера. Ошибка: {error.ErrorMessage}";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера. Ошибка: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }
                #endregion

                byte[]? dCert = _getCert.GetCertificateByCryptAcquireContext(hProv);

                if (dCert == null)
                {
                    string logMsg4 = $"Не найден сертификат в контейнере {container.Name}";
                    throw new CapiLiteCoreException("Не найден сертификат", CapiLiteCoreErrors.NotFaundCertificate);
                }

                using var cert = new CCertificate(dCert);

                #region password
                var asciiPinLength = Encoding.ASCII.GetByteCount(container.Pin);
                var asciiPin = stackalloc byte[asciiPinLength + 1];
                var dwParam = Constants.PP_SIGNATURE_PIN;
                Encoding.ASCII.GetBytes(container.Pin, new Span<byte>(asciiPin, asciiPinLength));
                string logMsg5 = $"Вызов метода CryptSetProvParam";

                if (!ADVAPI32Helper.CryptSetProvParam(hProv, dwParam, (nint)asciiPin, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg6 = $"Ошибка указания пина для закрытого ключа: {err.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка указания пина для закрытого ключа: {err.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }
                #endregion

                cert.SetProvider(container.Name, string.Empty);
                var containsKey = cert.ContainsPrivateKey;

                if (!containsKey)
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg7 = $"Ошибка получение признака наличия привязки закрытого ключа к сертификату. {err.ErrorMessage}";
                    throw new CapiLiteCoreException("Ошибка получение признака наличия привязки закрытого ключа к сертификату.", CapiLiteCoreErrors.NoValidCertificate);
                }

                signPara.dwSize = (uint)Marshal.SizeOf(typeof(XADES_SIGN_MESSAGE_PARA));
                var xadesSignPara = new XADES_SIGN_PARA();
                xadesSignPara.dwSize = (uint)Marshal.SizeOf(typeof(XADES_SIGN_PARA));
                uint dSignatureType = 0;
                uint dSignatureFormat = 0;

                switch (xadesType)
                {
                    case XadesType.ENVELOPED:
                        dSignatureType = Constants.XML_XADES_SIGNATURE_TYPE_ENVELOPED;
                        break;
                    case XadesType.ENVELOPING:
                        dSignatureType = Constants.XML_XADES_SIGNATURE_TYPE_ENVELOPING;
                        break;
                    case XadesType.TEMPLATE:
                        dSignatureType = Constants.XML_XADES_SIGNATURE_TYPE_TEMPLATE;
                        break;
                }

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

                if (signatureFormat == XadesFormat.XadesT || signatureFormat == XadesFormat.XadesXLongType1)
                //|| signatureFormat == XadesFormat.XadesA)
                {
                    var tspConnectionPara = new CADES_SERVICE_CONNECTION_PARA();
                    tspConnectionPara.dwSize = (uint)Marshal.SizeOf(tspConnectionPara);
                    var TSPAddressLength = OSHelper.EncodingGetByteCount(TSPAddress);
                    var TSPAddressRaw = stackalloc byte[TSPAddressLength + 1];
                    OSHelper.EncodingGetBytes(TSPAddress, new Span<byte>(TSPAddressRaw, TSPAddressLength));
                    tspConnectionPara.wszUri = (nint)TSPAddressRaw;
                    xadesSignPara.pTspConnectionPara = (nint)(&tspConnectionPara);
                }

                xadesSignPara.dwSignatureType = dSignatureType | dSignatureFormat;
                xadesSignPara.pSignerCert = cert.handle;
                string logMsg8 = $"Вызов метода XadesSign с параметрами: dSignatureType = {dSignatureType}, dSignatureFormat = {dSignatureFormat}, data.Length = {data.Length}";

                signPara.pXadesSignPara = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(XADES_SIGN_PARA)));
                Marshal.StructureToPtr(xadesSignPara, signPara.pXadesSignPara, true);

                if (!XadesHelper.XadesSign(
                   ref signPara,
                   0,
                   false,
                   data,
                   (uint)data.Length,
                   ref blob
                ))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    bool accessDenied = err.ErrorMessage.ToLower().Contains("access denied");

                    if (accessDenied && cert != null && cert.isPrivateKeyExpired)
                    {
                        err.ErrorMessage = $"{err.ErrorMessage} Возможная причина: истек срок действия закрытого ключа.";
                    }

                    string logMsg9 = $"Не удалось получить подпись Xades: {err.ErrorMessage}";
                    throw new CapiLiteCoreException($"Не удалось получить подпись Xades: {err.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                var strBlob = Marshal.PtrToStructure(blob, typeof(CRYPT_DATA_BLOB));

                if (strBlob is CRYPT_DATA_BLOB strBlobStruct)
                {
                    byte[] arr = new byte[strBlobStruct.cbData];
                    Marshal.Copy(strBlobStruct.pbData, arr, 0, strBlobStruct.cbData);
                    signMessage = arr;
                }

                signatureCreateResult.SignatureData = signMessage;
                signatureCreateResult.Success = true;
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

                if (blob != 0 && !XadesHelper.XadesFreeBlob(blob))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg12 = $"Ошибка освобождения структуры  CRYPT_DATA_BLOB: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }

                if (signPara.pXadesSignPara != 0)
                {
                    Marshal.FreeHGlobal(signPara.pXadesSignPara);
                }
            }

            return signatureCreateResult;
        }
    }
}
