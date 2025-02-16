using Crypto.Entities;
using CryptoProWrapper.GetSign;
using CryptoProWrapper.GetTspToken;
using CryptStructure;
using Microsoft.Extensions.Configuration;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;

namespace CryptoProWrapper
{
    public class LowLevelCadesDllSignature : IGetCadesSignature
    {
        private IGetTspToken _getTspToken;
        private readonly string TSPAddress;
        private IGetCertificate _getCert;

        public LowLevelCadesDllSignature(
            IGetTspToken getTspToken,
            IConfiguration configuration,
            IGetCertificate getCert)
        {
            _getCert = getCert;
            _getTspToken = getTspToken;
            string? tspA = "адрес TSP сервера"; 

            if (!string.IsNullOrEmpty(tspA))
            {
                TSPAddress = tspA;
            }
        }

        public List<KeyContainer> GetAllKeyContainers()
        {
            nint hProv = 0;
            nint certHProv = 0;
            uint providerType = 75;
            uint certProviderType = 80;
            int limit = 30;
            var result = new List<KeyContainer>();
            try
            {
                if (!ADVAPI32Helper.CryptAcquireContext(out hProv, null, null, providerType, Constants.CRYPT_VERIFYCONTEXT))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg1 = $"Не удалось получить дескриптор провайдера. Ошибка: {error.ErrorMessage}.";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера. Ошибка: {error.ErrorMessage}.", CapiLiteCoreErrors.InternalServerError);
                }

                uint pcbData = 90;
                uint dwFlags = Constants.CRYPT_FIRST;  //необходимо для инициализации

                int i = 0;

                while (i < limit)
                {
                    i++;


                    if (!ADVAPI32Helper.CryptGetProvParam(hProv, Constants.PP_ENUMCONTAINERS, null, ref pcbData, dwFlags))
                    {
                        var err = ExceptionHelper.GetLastPInvokeError();
                        string logMsg2 = $"Ошибка получения контейнера: {err.ErrorMessage}.";
                        break;
                    }

                    var buffer = new byte[pcbData];

                    if (!ADVAPI32Helper.CryptGetProvParam(hProv, Constants.PP_ENUMCONTAINERS, buffer, ref pcbData, dwFlags))
                    {
                        var err = ExceptionHelper.GetLastPInvokeError();
                        string logMsg3 = $"Ошибка получения контейнера: {err.ErrorMessage}";
                        break;
                    }

                    dwFlags = 0;//необходимо для продолжения перечисления
                    var containerName = System.Text.Encoding.UTF8.GetString(buffer);
                    result.Add(new KeyContainer { ContainerName = containerName.TrimEnd('\0') });
                }

                uint certDwFlags = Constants.CRYPT_SILENT;

                foreach (KeyContainer key in result)
                {
                    if (!ADVAPI32Helper.CryptAcquireContext(out certHProv, key.ContainerName, null, certProviderType, certDwFlags))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        string logMsg4 = $"Не удалось получить дескриптор провайдера для получения сертификата из контейнера  {key.ContainerName}. {error.ErrorMessage}";
                        continue;
                    }

                    byte[]? dCert = _getCert.GetCertificateByCryptAcquireContext(certHProv);

                    if (dCert != null)
                    {
                        using var cert = new CCertificate(dCert);
                        key.CertificateSerialNumber = cert.serialNumber;
                        key.CertificateSubject = cert.subject;
                    }
                }
            }
            catch (CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg5 = ex.Message;
                throw;
            }
            finally
            {
                if (hProv != 0 && !ADVAPI32Helper.CryptReleaseContext(hProv, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg6 = $"Ошибка освобождения контекста провайдера: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }

                if (certHProv != 0 && !ADVAPI32Helper.CryptReleaseContext(certHProv, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg7 = $"Ошибка освобождения контекста провайдера: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }

            return result;
        }

        /// <summary>
        /// https://habr.com/ru/articles/734368/
        /// </summary>
        /// <param name="cert"></param>
        /// <param name="data"></param>
        /// <param name="detachedSignature"></param>
        /// <returns></returns>
        /// <exception cref="CapiLiteCoreException"></exception>
        [SecuritySafeCritical]
        public unsafe SignatureCreateResult GetCadesBesSignature(CryptoContainer container, byte[] data, bool detachedSignature, bool includeCrl)
        {
            nint hProv = 0;
            nint hMsg = 0;
            var signatureCreateResult = new SignatureCreateResult();
            string logMsg1 = $"Начало GetCadesBesSignature";
            byte[]? signMessage = null;

            try
            {
                uint dwFlags = Constants.CRYPT_SILENT;
                string logMsg2 = $"Вызов метода CryptAcquireContext с параметрами: container.Name = {container.Name}; container.ProviderName = {container.ProviderName}; container.ProviderType = {container.ProviderType}";

                if (!ADVAPI32Helper.CryptAcquireContext(out hProv, container.Name, container.ProviderName, (uint)container.ProviderType, dwFlags))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg3 = $"Не удалось получить дескриптор провайдера. Ошибка: {error.ErrorMessage}. Параметры: container.Name = {container.Name}; container.ProviderName = {container.ProviderName}; container.ProviderType = {container.ProviderType}";
                    throw new CapiLiteCoreException($"Не удалось получить дескриптор провайдера", CapiLiteCoreErrors.InternalServerError);
                }

                byte[]? dCert = _getCert.GetCertificateByCryptAcquireContext(hProv);

                if (dCert == null || dCert.Length == 0)
                {
                    throw new CapiLiteCoreException("Не найден сертификат", CapiLiteCoreErrors.NotFaundCertificate);
                }

                using var cert = new CCertificate(dCert);

                //string hashPin = OSHelper.ComputeSHA1Hash(container.Pin);
                var asciiPinLength = Encoding.ASCII.GetByteCount(container.Pin);
                //var asciiPinLength = Encoding.ASCII.GetByteCount(container.Pin);
                var asciiPin = stackalloc byte[asciiPinLength + 1];
                Encoding.ASCII.GetBytes(container.Pin, new Span<byte>(asciiPin, asciiPinLength));
                //Encoding.ASCII.GetBytes(container.Pin, new Span<byte>(asciiPin, asciiPinLength));

                string logMsg4 = $"Вызов метода CryptSetProvParam";

                if (!ADVAPI32Helper.CryptSetProvParam(hProv, Constants.PP_KEYEXCHANGE_PIN, (nint)asciiPin, 0))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg5 = $"Ошибка указания пина для закрытого ключа: {error.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка указания пина для закрытого ключа: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                #region задаем параметры подписи
                var certContext = cert.context;//new ReadOnlySpan<CryptStructure.CERT_CONTEXT>(cert.Handle.ToPointer(), 1);
                var signerCertBlob = new CRYPT_INTEGER_BLOB
                {
                    cbData = (uint)certContext.cbCertEncoded,
                    pbData = (nint)certContext.pbCertEncoded
                };
                // prepare CMSG_SIGNER_ENCODE_INFO structure
                var signerInfo = new CMSG_SIGNER_ENCODE_INFO();
                signerInfo.cbSize = (uint)Marshal.SizeOf(signerInfo);
                signerInfo.pCertInfo = (nint)certContext.pCertInfo;
                signerInfo.hCryptProv = hProv;
                signerInfo.dwKeySpec = Constants.AT_KEYEXCHANGE;
                string Oid = cert.HashAlgorithmOid;//Constants.szOID_CP_GOST_R3411
                var digestOidLength = Encoding.ASCII.GetByteCount(Oid);
                var digestOidRaw = stackalloc byte[digestOidLength + 1];
                Encoding.ASCII.GetBytes(Oid, new Span<byte>(digestOidRaw, digestOidLength));
                signerInfo.HashAlgorithm.pszObjId = (nint)digestOidRaw;
                // prepare CMSG_SIGNED_ENCODE_INFO structure
                var signedInfo = new CMSG_SIGNED_ENCODE_INFO();
                signedInfo.cbSize = (uint)Marshal.SizeOf(signedInfo);
                signedInfo.cSigners = 1;
                signedInfo.rgSigners = (nint)(&signerInfo);
                signedInfo.cCertEncoded = 1;
                signedInfo.rgCertEncoded = (nint)(&signerCertBlob);
                var cadesInfo = new CADES_ENCODE_INFO();
                cadesInfo.dwSize = (uint)Marshal.SizeOf(cadesInfo);
                cadesInfo.pSignedEncodeInfo = (nint)(&signedInfo);
                #endregion

                // Открываем дескриптор сообщения для создания усовершенствованной подписи
                if (detachedSignature)
                {
                    //hMsg = Crypt32Helper.CryptMsgOpenToEncode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING,
                    //    Constants.CMSG_DETACHED_FLAG, Constants.CMSG_SIGNED, (nint)(&signedInfo), null, 0);//открепленная CMS
                    string logMsg6 = $"Вызов метода CadesMsgOpenToEncode с флагом CMSG_DETACHED_FLAG";
                    hMsg = CadesHelper.CadesMsgOpenToEncode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, Constants.CMSG_DETACHED_FLAG
                       , (nint)(&cadesInfo), null, 0);//открепленная CADES
                }
                else
                {
                    //hMsg = Crypt32Helper.CryptMsgOpenToEncode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING,
                    //Constants.CPCMSG_CADES_STRICT, Constants.CMSG_SIGNED, (nint)(&signedInfo), null, 0); // прикрепленная CMS
                    string logMsg7 = $"Вызов метода CadesMsgOpenToEncode без флага CMSG_DETACHED_FLAG";
                    hMsg = CadesHelper.CadesMsgOpenToEncode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0
                      , (nint)(&cadesInfo), null, 0);//открепленная CADES
                }

                if (hMsg == 0)
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg8 = $"Ошибка открытия дискриптора сообщения для создания усовершенствованной подписи: {err.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка открытия дискриптора сообщения для создания усовершенствованной подписи: {err.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                // Формируем подпись в сообщении
                fixed (byte* pData = data)
                {
                    string logMsg8 = $"Вызов метода CryptMsgUpdate с параметрами: hMsg = {hMsg}, data.Length = {data.Length}";

                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true))
                    {
                        var err = ExceptionHelper.GetLastPInvokeError();
                        string logMsg9 = $"Ошибка формирования подписи в сообщении: {err.ErrorMessage}";
                        throw new CapiLiteCoreException($"Ошибка формирования подписи в сообщении: {err.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                // Получаем размер подписи
                int mSize = 0;
                string logMsg10 = $"Вызов метода CryptMsgGetParam с параметрами: hMsg = {hMsg}";

                if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_CONTENT_PARAM, 0, 0, ref mSize))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    bool accessDenied = err.ErrorMessage.ToLower().Contains("access denied");
                    if (accessDenied && cert != null && cert.isPrivateKeyExpired)
                    {
                        err.ErrorMessage = $"{err.ErrorMessage} Возможная причина: истек срок действия закрытого ключа.";
                    }

                    string logMsg11 = $"Ошибка получения размера подписи: {err.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка получения размера подписи: {err.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                // Получаем подпись
                signMessage = new byte[mSize];

                fixed (byte* pSignature = signMessage)
                {
                    string logMsg12 = $"Повторный вызов метода CryptMsgGetParam с параметрами: hMsg = {hMsg}, mSize = {mSize}";

                    if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_CONTENT_PARAM, 0, (nint)pSignature, ref mSize))
                    {
                        var err = ExceptionHelper.GetLastPInvokeError();
                        bool accessDenied = err.ErrorMessage.ToLower().Contains("access denied");
                        if (accessDenied && cert != null && cert.isPrivateKeyExpired)
                        {
                            err.ErrorMessage = $"{err.ErrorMessage} Возможная причина: истек срок действия закрытого ключа.";
                        }

                        string logMsg13 = $"Ошибка получения подписи: {err.ErrorMessage}";
                        throw new CapiLiteCoreException($"Ошибка получения подписи: {err.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                    }
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
                string logMsg14 = ex.Message;
                throw;
            }
            finally
            {
                if (hProv != 0 && !ADVAPI32Helper.CryptReleaseContext(hProv, 0))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg15 = $"Ошибка освобождения контекста провайдера: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }

                if (hMsg != 0 && !Crypt32Helper.CryptMsgClose(hMsg))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg16 = $"Ошибка освобождения контекста дескриптора сообщения: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }

            return signatureCreateResult;
        }

        [SecuritySafeCritical]
        public unsafe void EnchanceSignature(SignatureCreateResult signature, CadesFormat signatureFormat)
        {
            nint hMsg = 0;
            nint hInfo = 0;
            var encodedAttr = (nint)0;

            if (signature.SignatureData == null)
            {
                string logMsg1 = "Отсутствует подпись, которую необходимо усовершенствовать";
                throw new CapiLiteCoreException("Отсутствует подпись, которую необходимо усовершенствовать", CapiLiteCoreErrors.BadRequest);
            }

            byte[] signMessage = signature.SignatureData;
            string logMsg2 = $"Начало GetCadesSignature";

            try
            {
                string logMsg3 = $"Вызов метода CryptMsgOpenToDecode";
                hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);

                if (hMsg == 0)
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg4 = $"Ошибка открытия криптографического сообщения для декодирования подписи чтобы ее усовершенствовать: {err.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка открытия криптографического сообщения для декодирования подписи чтобы ее усовершенствовать: {err.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                // Добавляем подпись в сообщение
                fixed (byte* pSignMessage = signMessage)
                {
                    string logMsg5 = $"Вызов метода CryptMsgUpdate с параметрами: signMessage.Length = {signMessage.Length}";

                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSignMessage, (uint)signMessage.Length, true))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        string logMsg6 = $"Ошибка добавление подписи в сообщение: {error.SystemErrorDescription}";
                        throw new CapiLiteCoreException($"Ошибка добавление подписи в сообщение: {error.SystemErrorDescription}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                var tspConnectionPara = new CADES_SERVICE_CONNECTION_PARA();
                tspConnectionPara.dwSize = (uint)Marshal.SizeOf(tspConnectionPara);
                var TSPAddressLength = OSHelper.EncodingGetByteCount(TSPAddress);
                var TSPAddressRaw = stackalloc byte[TSPAddressLength + 1];
                OSHelper.EncodingGetBytes(TSPAddress, new Span<byte>(TSPAddressRaw, TSPAddressLength));
                tspConnectionPara.wszUri = (nint)TSPAddressRaw;
                var signParaT = new CADES_SIGN_PARA();
                signParaT.dwSize = (uint)Marshal.SizeOf(signParaT);

                switch (signatureFormat)
                {
                    case CadesFormat.CadesT:
                        signParaT.dwCadesType = Constants.CADES_T;
                        break;
                    case CadesFormat.CadesA:
                        signParaT.dwCadesType = Constants.CADES_A;
                        break;
                    case CadesFormat.CadesXLongType1:
                        //case CadesFormat.CadesXLongType2:
                        signParaT.dwCadesType = Constants.CADES_X_LONG_TYPE_1;
                        break;
                }

                signParaT.pTspConnectionPara = (nint)(&tspConnectionPara);
                string logMsg7 = $"Вызов метода CadesMsgEnhanceSignatureAll с параметрами: CadesType = {signParaT.dwCadesType}, TSPAddress = {TSPAddress}";

                //todo: понадобится когда захотим создавать подпись cades-xl1 на сертефикате, у которого нет адресов ocsp
                //if (signatureFormat == CadesFormat.CadesXLongType1)
                //{
                //    string OCSPAddress = "http://testca.cryptopro.ru/ocsp/ocsp.srf";
                //    signParaT.cAdditionalOCSPServices = 1;
                //    var OCSPAddressLength = OSHelper.EncodingGetByteCount(OCSPAddress);
                //    byte* OCSPAddressRaw = stackalloc byte[OCSPAddressLength + 1];
                //    OSHelper.EncodingGetBytes(OCSPAddress, new Span<byte>(OCSPAddressRaw, OCSPAddressLength));
                //    signParaT.rgAdditionalOCSPServices = (nint)(&OCSPAddressRaw);
                //}

                if (!CadesHelper.CadesMsgEnhanceSignatureAll(hMsg, (nint)(&signParaT)))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg8 = $"Ошибка усовершенствования подписи Cades: {error.LastErrorCode} {error.SystemErrorDescription}";
                    throw new CapiLiteCoreException($"Ошибка получение усовершенствованной подписи: {error.LastErrorCode} - {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                #region заморозили CadesXLongType2
                //if (signatureFormat == CadesFormat.CadesXLongType2)
                //{
                //    CryptographicAttributeObject certificateRefsAttr = null;
                //    //var certificateRefsCryptAttr = new CRYPT_ATTRIBUTE();
                //    CryptographicAttributeObject revocationRefsAttr = null;
                //    //var revocationRefsCryptAttr = new CRYPT_ATTRIBUTE();

                //    #region трансформация атрибутов
                //    var signerCount = 0U;
                //    var signerCountSize = Marshal.SizeOf(signerCount);
                //    if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_COUNT_PARAM, 0, (nint)(&signerCount), ref signerCountSize))
                //    {
                //        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //        throw new CapiLiteCoreException($"Ошибка получения подписывателей: {error}");
                //    }

                //    if (signerCount == 0)
                //    {
                //        throw new CapiLiteCoreException($"Ошибка подпись не содержит подписывателя");
                //    }

                //    for (var signerIndex = 0U; signerIndex < signerCount; signerIndex++)
                //    {
                //        var signerInfoSize = 0;
                //        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, signerIndex, 0, ref signerInfoSize))
                //        {
                //            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}");
                //        }
                //        hInfo = Marshal.AllocHGlobal((int)signerInfoSize);
                //        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, signerIndex, hInfo, ref signerInfoSize))
                //        {
                //            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}");
                //        }
                //        var pSignerInfo = (CMSG_SIGNER_INFO)Marshal.PtrToStructure(hInfo, typeof(CMSG_SIGNER_INFO));
                //        //CryptographicAttributeObjectCollection unsignedAttributes = ReadCryptoAttrsCollection(pSignerInfo.UnauthAttrs);

                //        int certInfoSize = 0;
                //        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_CERT_PARAM, signerIndex, 0, ref certInfoSize))
                //        {
                //            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //            throw new CapiLiteCoreException($"Ошибка извлечения сертификата подписывателя {signerIndex}: {error}");
                //        }

                //        var encryptedCert = new byte[certInfoSize];
                //        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_CERT_PARAM, signerIndex, encryptedCert, ref certInfoSize))
                //        {
                //            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //            throw new CapiLiteCoreException($"Ошибка извлечения сертификата подписывателя {signerIndex}: {error}");
                //        }

                //        using var signerCert = new CCertificate(encryptedCert);
                //        string hashOid = signerCert.HashAlgorithmOid;

                //        for (int unsignedAttributeIndex = 0; unsignedAttributeIndex < pSignerInfo.UnauthAttrs.cAttr; unsignedAttributeIndex++)
                //        {
                //            nint hAttr = new IntPtr((long)pSignerInfo.UnauthAttrs.rgAttr + (unsignedAttributeIndex * Marshal.SizeOf(typeof(CRYPT_ATTRIBUTE))));
                //            CRYPT_ATTRIBUTE pAttr = (CRYPT_ATTRIBUTE)Marshal.PtrToStructure(hAttr, typeof(CRYPT_ATTRIBUTE));

                //            switch (pAttr.pszObjId)
                //            {
                //                case Constants.SignatureTimeStampAttibuteOid:
                //                    //case Constants.EscTimeStampAttributeOid:
                //                    #region удаление атрибута CAdES-C-time-stamp
                //                    var delPara = new CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR_PARA();
                //                    delPara.cbSize = (uint)Marshal.SizeOf(delPara);
                //                    delPara.dwSignerIndex = signerIndex;
                //                    delPara.dwUnauthAttrIndex = (uint)unsignedAttributeIndex;

                //                    if (!Crypt32Helper.CryptMsgControl(hMsg, 0, Constants.CMSG_CTRL_DEL_SIGNER_UNAUTH_ATTR, new IntPtr(&delPara)))
                //                    {
                //                        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //                        throw new CapiLiteCoreException($"Ошибка удаления атрибута штампа времени CAdES-C (на доказательства): {error}");
                //                    }
                //                    #endregion
                //                    break;
                //                case Constants.CertificateRefsAttibuteOid:
                //                    certificateRefsAttr = new CryptographicAttributeObject(new Oid(pAttr.pszObjId), GetAsnEncodedDataCollection(pAttr));
                //                    break;
                //                case Constants.RevocationRefsAttibuteOid:
                //                    revocationRefsAttr = new CryptographicAttributeObject(new Oid(pAttr.pszObjId), GetAsnEncodedDataCollection(pAttr));
                //                    break;
                //            }
                //        }

                //        #region получение штампа времени на объединение значений для атрибутов "complete-certificate-references" и "complete-revocation-references"
                //        var encryptedDigestSize = 0;
                //        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_ENCRYPTED_DIGEST, 0, 0, ref encryptedDigestSize))
                //        {
                //            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //            throw new CapiLiteCoreException($"Ошибка извлечения хэша подписи: {error}");
                //        }
                //        var encryptedDigest = new byte[encryptedDigestSize];
                //        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_ENCRYPTED_DIGEST, 0, encryptedDigest, ref encryptedDigestSize))
                //        {
                //            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //            throw new CapiLiteCoreException($"Ошибка извлечения хэша подписи: {error}");
                //        }

                //        var toTsp = new List<byte[]>();
                //        toTsp.Add(encryptedDigest);
                //        uint tokenSize;
                //        byte[] tspToken = _getTspToken.GetTspToken(TSPAddress, toTsp, hashOid, out tokenSize);
                //        //nint tspToken = _getTspToken.GetTspToken(TSPAddress, toTsp, hashOid, out tokenSize);
                //        #endregion

                //        #region добавление атрибута CAdES-C-time-stamped-certs-crls-references
                //        fixed (byte* pzdObjId = System.Text.Encoding.UTF8.GetBytes(Constants.SignatureTimeStampAttibuteOid), pTst = tspToken)
                //        {
                //            var tstBlob = new CRYPT_ATTR_BLOB();//CRYPT_INTEGER_BLOB   CRYPT_ATTR_BLOB
                //            tstBlob.cbData = (uint)tspToken.Length;
                //            tstBlob.pbData = (nint)pTst;
                //            var tstAttr = new CRYPT_ATTRIBUTE();
                //            tstAttr.pszObjId = Constants.SignatureTimeStampAttibuteOid;
                //            tstAttr.cValue = 1;
                //            tstAttr.rgValue = (nint)(&tstBlob);
                //            var encodedAttrLen = 0U;
                //            Crypt32Helper.CryptEncodeObjectEx(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, Constants.PKCS_ATTRIBUTE,
                //                (nint)(&tstAttr), Constants.CRYPT_ENCODE_ALLOC_FLAG, 0, (nint)(&encodedAttr), (nint)(&encodedAttrLen));

                //            if (encodedAttr == 0)
                //            {
                //                string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //                throw new CapiLiteCoreException($"Ошибка кодирования атрибута штампа времени: {error}");
                //            }
                //            //cryptBlob.cbData = token.Length;
                //            //fixed (byte* ptoken = token)
                //            //{
                //            //    cryptBlob.pbData = (nint)ptoken;
                //            //    //var newAttr = new CRYPT_ATTRIBUTE();
                //            //    //newAttr.pszObjId = Constants.SignatureTimeStampAttibuteOid;
                //            //    //newAttr.cValue = 1;
                //            //    //newAttr.rgValue = (nint)(&cryptBlob);
                //            //}
                //            var addPara = new CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR_PARA();
                //            addPara.cbSize = (uint)Marshal.SizeOf(addPara);
                //            addPara.dwSignerIndex = signerIndex;
                //            addPara.blob.cbData = (int)encodedAttrLen;
                //            addPara.blob.pbData = encodedAttr;

                //            if (!Crypt32Helper.CryptMsgControl(hMsg, 0, Constants.CMSG_CTRL_ADD_SIGNER_UNAUTH_ATTR, (nint)(&addPara)))
                //            {
                //                string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                //                throw new CapiLiteCoreException($"Ошибка добавления атрибута штампа времени: {error}");
                //            }
                //        }
                //        #endregion
                //    }
                //    #endregion
                //}
                #endregion

                // Получаем размер подписи
                string logMsg9 = $"Вызов метода CryptMsgGetParam";
                int mSizeD = 0;

                if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_ENCODED_MESSAGE, 0, 0, ref mSizeD))
                {
                    var error = ExceptionHelper.GetLastPInvokeError();
                    string logMsg10 = $"Ошибка получения размера усовершенствованной подписи подписи: {error.ErrorMessage}";
                    throw new CapiLiteCoreException($"Ошибка получения размера усовершенствованной подписи подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                }

                // Получаем подпись
                string logMsg11 = $"Повторный вызов метода CryptMsgGetParam с парамтреми: mSizeD = {mSizeD}";
                byte[] enchanceSignMessage = new byte[mSizeD];

                fixed (byte* pSignature = enchanceSignMessage)
                {
                    if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_ENCODED_MESSAGE, 0, (nint)pSignature, ref mSizeD))
                    {
                        var error = ExceptionHelper.GetLastPInvokeError();
                        string logMsg12 = $"Ошибка получения усовершенствованной подписи: {error.ErrorMessage}";
                        throw new CapiLiteCoreException($"Ошибка получения усовершенствованной подписи: {error.ErrorMessage}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                signature.Success = true;
                signature.SignatureData = enchanceSignMessage;
            }
            catch (CapiLiteCoreException ex)
            {
                string logMsg13 = $"Ошибка усовершенствования подписи Cades: {ex.Message}";
                signature.Error = ex.Message;
                signature.Success = false;
                signature.SignatureData = null;
                throw;
            }
            catch (Exception ex)
            {
                string logMsg14 = $"Ошибка усовершенствования подписи Cades: {ex.Message}";
                signature.Success = false;
                signature.Error = "Ошибка усовершенствования подписи Cades";
                signature.SignatureData = null;
                throw;
            }
            finally
            {
                if (hMsg != 0 && !Crypt32Helper.CryptMsgClose(hMsg))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg15 = $"Ошибка освобождения дескриптора сообщения: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }

                if (hInfo != 0) Marshal.FreeHGlobal(hInfo);
                if (encodedAttr != 0) Marshal.FreeHGlobal(encodedAttr);
            }
        }

        [SecuritySafeCritical]
        public unsafe void DisplayAttachedSignature(byte[] sig)
        {
            nint hMsg = 0;

            try
            {
                hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
                if (hMsg == 0)
                {
                    string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                    string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                    throw new CapiLiteCoreException($"Ошибка открытия дискриптора подписи для декодирования: {PInvokeError}; {Kernel32Error}", CapiLiteCoreErrors.InternalServerError);
                }

                fixed (byte* pSig = sig)
                {
                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSig, (uint)sig.Length, true))
                    {
                        string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                        string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка декодирования подписи: {PInvokeError}; {Kernel32Error}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                if (!CadesHelper.CadesMsgUIDisplaySignature(hMsg, 0, 0, "Signature"))
                {
                    string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                    string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                    throw new CapiLiteCoreException($"Ошибка отображения подписи: {PInvokeError}; {Kernel32Error}", CapiLiteCoreErrors.InternalServerError);
                }
            }
            finally
            {
                if (hMsg != 0 && !Crypt32Helper.CryptMsgClose(hMsg))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg1 = $"Ошибка освобождения дескриптора сообщения: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }
        }

        [SecuritySafeCritical]
        public unsafe void DisplayDetachedSignature(byte[] sig)
        {
            nint hMsg = 0;

            try
            {
                hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);
                if (hMsg == 0)
                {
                    string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                    string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                    throw new CapiLiteCoreException($"Ошибка открытия дискриптора подписи для декодирования: {PInvokeError}; {Kernel32Error}", CapiLiteCoreErrors.InternalServerError);
                }

                fixed (byte* pSig = sig)
                {
                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSig, (uint)sig.Length, true))
                    {
                        string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                        string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка декодирования подписи: {PInvokeError}; {Kernel32Error}", CapiLiteCoreErrors.InternalServerError);
                    }
                }

                if (!CadesHelper.CadesMsgUIDisplaySignature(hMsg, 0, 0, "Signature"))
                {
                    string PInvokeError = Crypt32Helper.GetErrorDescription((uint)Marshal.GetLastPInvokeError());
                    string Kernel32Error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                    throw new CapiLiteCoreException($"Ошибка отображения подписи: {PInvokeError}; {Kernel32Error}", CapiLiteCoreErrors.InternalServerError);
                }
            }
            finally
            {
                if (hMsg != 0 && !Crypt32Helper.CryptMsgClose(hMsg))
                {
                    var err = ExceptionHelper.GetLastPInvokeError();
                    string logMsg1 = $"Ошибка освобождения дескриптора сообщения: {err.LastErrorCode}. {err.SystemErrorDescription}";
                }
            }
        }

        [SecurityCritical]
        internal static byte[] BlobToByteArray(CRYPTOAPI_BLOB blob)
        {
            if (blob.cbData == 0)
            {
                return new byte[0];
            }
            byte[] destination = new byte[blob.cbData];
            Marshal.Copy(blob.pbData, destination, 0, destination.Length);
            return destination;
        }

        [SecurityCritical]
        internal static byte[] BlobToByteArray(IntPtr pBlob)
        {
            CRYPTOAPI_BLOB? blob = (CRYPTOAPI_BLOB?)Marshal.PtrToStructure(pBlob, typeof(CRYPTOAPI_BLOB));

            if (blob == null || blob.Value.cbData == 0)
            {
                return new byte[0];
            }
            return BlobToByteArray(blob.Value);
        }

        private Pkcs9AttributeObject Pkcs9AttributeFromOID(string? _sName)
        {
            switch (_sName)
            {
                //case UCConsts.S_SIGN_DATE_OID: return new Pkcs9SigningTime();
                //        case UConsts.S_CONTENT_TYPE_OID : return new Pkcs9ContentType();      ->> в Mono падает                          
                //        case UConsts.S_MESS_DIGEST_OID  : return new Pkcs9MessageDigest();
                default: return new Pkcs9AttributeObject();
            }
        }

        /// <summary>
        /// Формирует коллекуцию ASN
        /// </summary>
        /// <param name="_pAttr">Структура</param>
        /// <returns>Коллекция</returns>
        private AsnEncodedDataCollection GetAsnEncodedDataCollection(CRYPT_ATTRIBUTE _pAttr)
        {
            AsnEncodedDataCollection pRes = new AsnEncodedDataCollection();
            Oid pOid = new Oid(_pAttr.pszObjId);
            string? sOid = pOid.Value;
            for (uint i = 0; i < _pAttr.cValue; i++)
            {
                checked
                {
                    IntPtr pAttributeBlob = new IntPtr((long)_pAttr.rgValue + (i * Marshal.SizeOf(typeof(CryptStructure.CRYPTOAPI_BLOB))));
                    Pkcs9AttributeObject attribute = new Pkcs9AttributeObject(pOid, BlobToByteArray(pAttributeBlob));
                    Pkcs9AttributeObject customAttribute = Pkcs9AttributeFromOID(sOid);
                    if (customAttribute != null)
                    {
                        customAttribute.CopyFrom(attribute);
                        attribute = customAttribute;
                    }
                    pRes.Add(attribute);
                }
            }
            return pRes;
        }

        /// <summary>
        /// Получить список атрибутов подписи
        /// </summary>
        /// <param name="_pAttrs">Структура атрибутов</param>
        /// <returns>Коллекция атрибутов</returns>
        private CryptographicAttributeObjectCollection ReadCryptoAttrsCollection(CRYPT_ATTRIBUTES _pAttrs)
        {
            CryptographicAttributeObjectCollection pRes = new CryptographicAttributeObjectCollection();
            for (int i = 0; i < _pAttrs.cAttr; i++)
            {
                IntPtr hAttr = new IntPtr((long)_pAttrs.rgAttr + (i * Marshal.SizeOf(typeof(CRYPT_ATTRIBUTE))));
                var pAttr = (CRYPT_ATTRIBUTE?)Marshal.PtrToStructure(hAttr, typeof(CRYPT_ATTRIBUTE));

                if (pAttr != null)
                {
                    CryptographicAttributeObject pAttrInfo = new CryptographicAttributeObject(new Oid(pAttr.Value.pszObjId), GetAsnEncodedDataCollection(pAttr.Value));
                    pRes.Add(pAttrInfo);
                }
            }
            return pRes;
        }
    }
}
