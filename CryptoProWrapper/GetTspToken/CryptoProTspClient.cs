using Crypto.Entities;
using Crypto.Pivot;
using CryptStructure;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace CryptoProWrapper.GetTspToken
{
    public class CryptoProTspClient : IGetTspToken
    {
        public CryptoProTspClient()
        {
        }

        [SecuritySafeCritical]
        public unsafe byte[] GetTspToken(string TSPAddress, List<byte[]> texts, string hashOid, out uint tokenSize)
        {
            IntPtr tspMessage = IntPtr.Zero;
            nint hMsg = 0;
            tokenSize = 0;
            using var cStore = new CStore();
            byte[]? encryptedDigest = null;

            if (!cStore.OpenSystem(StoreNameType.Root, Constants.CERT_SYSTEM_STORE_CURRENT_USER))
            //if (!cStore.OpenSystem(StoreNameType.Root))
            {
                string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                throw new CapiLiteCoreException($"Ошибка открытия хранилища сертификатов доверительных корневых центров: {error}", CapiLiteCoreErrors.InternalServerError);
            }
            //string CN = "Ben";
            string CN = "CRYPTO-PRO Test Center 2";
            //string CN = "ГУП \"Центр информационных технологий РТ\"";
            //string serialNumberUC = "37418882f539a5924ad44e3de002ea3c";
            nint pCertContext = 0;
            try
            {
                var serialNumberUCLength = Encoding.UTF32.GetByteCount(CN);
                var serialNumberUCRaw = stackalloc byte[serialNumberUCLength + 1];
                Encoding.UTF32.GetBytes(CN, new Span<byte>(serialNumberUCRaw, serialNumberUCLength));
                pCertContext = Crypt32Helper.CertFindCertificateInStore(cStore.handle, Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING,
                            0, Constants.CERT_FIND_SUBJECT_STR, (nint)serialNumberUCRaw, 0);

                if (pCertContext == 0)
                {
                    PInvokeExcetion error = ExceptionHelper.GetLastPInvokeError();

                    if (string.IsNullOrEmpty(error.ErrorMessage))
                    {
                        throw new CapiLiteCoreException($"Ошибка получение сертификата УЦ: {error.SystemErrorDescription}", CapiLiteCoreErrors.IntegrationTSPError);
                    }
                    else
                    {
                        throw new CapiLiteCoreException(error.ErrorMessage, CapiLiteCoreErrors.InternalServerError);
                    }
                }

                //using var trustedCert = new CCertificate(pCertContext);
                //TSPAddress = "http://testca.cryptopro1.ru/tsp/tsp.srf";
                var TSPAddressLength = OSHelper.EncodingGetByteCount(TSPAddress);
                var TSPAddressRaw = stackalloc byte[TSPAddressLength + 1];
                OSHelper.EncodingGetBytes(TSPAddress, new Span<byte>(TSPAddressRaw, TSPAddressLength));
                var digestOidLength = Encoding.ASCII.GetByteCount(hashOid);
                var digestOidRaw = stackalloc byte[digestOidLength + 1];
                Encoding.ASCII.GetBytes(hashOid, new Span<byte>(digestOidRaw, digestOidLength));

                //var toTsp = new List<sbyte[]>();

                //foreach (byte[] textBytes in texts)
                //{
                //    string s = System.Text.Encoding.UTF8.GetString(textBytes, 0, textBytes.Length);
                //    var attrValue = new sbyte[textBytes.Length];
                //    Buffer.BlockCopy(textBytes, 0, attrValue, 0, textBytes.Length);
                //    toTsp.Add(attrValue);
                //}

                //var toTimeStamp = new TO_TIME_STAMP[texts.Count];

                //for (int t = 0; t < toTsp.Count; t++)
                //{
                //    toTimeStamp[t] = new TO_TIME_STAMP { text = toTsp[t], textLength = (uint)texts[t].Length };
                //}

                nint pHealthResult = TSPClientHelper.HealthCheck();
                string? healthResult = Marshal.PtrToStringAnsi(pHealthResult);
                nint Stamp = 0;
                nint Request = 0;

                try
                {
                    //nint pError = TSPClientHelper.CRequestCreate(out Request);
                    //string error = Marshal.PtrToStringAnsi(pError);
                    Request = TSPClientHelper.CRequestCreate();
                    var re = TSPClientHelper.CRequestPutTspAddress(Request, (nint)TSPAddressRaw);

                    if (re == 0)
                    {
                        throw new CapiLiteCoreException("Не удалось передать адрес TSP сервера в TSP клиент", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    re = TSPClientHelper.CRequestPutDataHashAlg(Request, (nint)digestOidRaw);

                    if (re == 0)
                    {
                        throw new CapiLiteCoreException("Не удалось передать хеш алгоритм в TSP клиент", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    foreach (byte[] textBytes in texts)
                    {
                        //Этот вариант нужно проверить
                        var attrValue = new sbyte[textBytes.Length];
                        Buffer.BlockCopy(textBytes, 0, attrValue, 0, textBytes.Length);
                        fixed (byte* pData = textBytes)
                        {
                            var newToTimeStamp = new TO_TIME_STAMP { text = (nint)pData, textLength = (uint)texts[0].Length };

                            re = TSPClientHelper.CRequestAddData(Request, (nint)(&newToTimeStamp));

                            if (re == 0)
                            {
                                throw new CapiLiteCoreException("Не удалось передать данные для подписи в TSP клиент", CapiLiteCoreErrors.IntegrationTSPError);
                            }
                        }

                        //Рабочий вариант, но с warning
                        //var attrValue = new sbyte[textBytes.Length];
                        //Buffer.BlockCopy(textBytes, 0, attrValue, 0, textBytes.Length);
                        //var newToTimeStamp = new TO_TIME_STAMP { text = attrValue, textLength = (uint)texts[0].Length };
                        //re = TSPClientHelper.CRequestAddData(Request, (nint)(&newToTimeStamp));

                        //if (re == 0)
                        //{
                        //    throw new CapiLiteCoreException("Не удалось передать данные для подписи в TSP клиент");
                        //}
                    }

                    re = TSPClientHelper.CRequestPutClientCertificate(Request, pCertContext);

                    if (re == 0)
                    {
                        throw new CapiLiteCoreException("Не удалось передать сертификат в TSP клиент", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    Stamp = TSPClientHelper.CStampCreate(Request);

                    int httpStatusCode = TSPClientHelper.CRequestGetHTTPStatus(Request);

                    if (Stamp == 0)
                    {
                        throw new CapiLiteCoreException($"Не удалось получить ответ от TSP серера у TSP клиента. HttpStatusCode = {httpStatusCode}", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    var failCode = TSPClientHelper.CStampGetFailInfo(Stamp);
                    var statusCode = TSPClientHelper.CStampGetStatus(Stamp);
                    nint status = TSPClientHelper.CStampGetStatusString(Stamp);
                    string? statusMessage = Marshal.PtrToStringAnsi(status);

                    if (statusCode > 0)
                    {
                        throw new CapiLiteCoreException($"Статус ответа от TSP сервера: {statusCode}. {statusMessage}", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    var st = TSPClientHelper.CStampVerify(Stamp, pCertContext);

                    if (st == 0)
                    {
                        throw new CapiLiteCoreException("Не удалось проверить ответ от TSP серера у TSP клиента", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    //string CStampVerifyMessage = Marshal.PtrToStringAnsi(CStampVerifyError);
                    tokenSize = TSPClientHelper.CStampGetTokenLength(Stamp);

                    if (tokenSize == 0)
                    {
                        throw new CapiLiteCoreException("Не удалось получить размер токена от TSP серера у TSP клиента", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    byte[] tokenBytes = new byte[tokenSize];
                    //re = TSPClientHelper.CStampGetToken(Stamp, tokenSize, tokenBytes);
                    //fixed (byte* pTokenBytes = tokenBytes)
                    //{
                    //    re = TSPClientHelper.CStampGetToken(Stamp, tokenSize, (nint)pTokenBytes);
                    //}
                    //string baseToken = Convert.ToBase64String(tokenBytes);

                    //token = TSPClientHelper.CStampGetToken(Stamp, tokenSize);
                    //nint ptoken = 0;
                    re = TSPClientHelper.CStampGetToken(Stamp, tokenSize, ref tspMessage);
                    Marshal.Copy(tspMessage, tokenBytes, 0, (int)tokenSize);

                    string fileName = @"/app/2.token";
                    //var re = Convert.ToBase64String(signatureCreateResult.SignatureData);
                    using (FileStream fstream = new FileStream($"{fileName}", FileMode.OpenOrCreate))
                    {
                        // запись массива байтов в файл
                        fstream.Write(tokenBytes, 0, (int)tokenSize);
                    }

                    if (tspMessage == IntPtr.Zero)
                    {
                        throw new CapiLiteCoreException("У TSP клиента не удалось получить токен от TSP серера.", CapiLiteCoreErrors.IntegrationTSPError);
                    }

                    //var tsContext = new ReadOnlySpan<CRYPT_TIMESTAMP_CONTEXT>(token.ToPointer(), 1);
                    //var tst = new ReadOnlySpan<byte>(tsContext[0].pbEncoded.ToPointer(), (int)tsContext[0].cbEncoded);

                    #region получение значение токена из подписи TSP
                    hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING, 0, 0, 0, 0, 0);

                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, tspMessage, tokenSize, true))
                    {
                        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка добавление подписи в сообщение: {error}", CapiLiteCoreErrors.InternalServerError);
                    }

                    var encryptedDigestSize = 0;
                    if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, 0, 0, ref encryptedDigestSize))
                    {
                        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка извлечения хэша подписи: {error}", CapiLiteCoreErrors.BadRequest);
                    }
                    encryptedDigest = new byte[encryptedDigestSize];
                    if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, 0, encryptedDigest, ref encryptedDigestSize))
                    {
                        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка извлечения хэша подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                    }
                    #endregion
                }
                finally
                {
                    TSPClientHelper.CRequestDelete(Request);
                    TSPClientHelper.CStampDelete(Stamp);
                }
            }
            finally
            {
                if (pCertContext != 0) Crypt32Helper.CertFreeCertificateContext(pCertContext);
                Crypt32Helper.CryptMsgClose(hMsg);
            }

            return encryptedDigest;
        }
    }
}
