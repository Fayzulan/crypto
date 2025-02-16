using CryptStructure;
using System.Buffers;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;

namespace CryptoProWrapper.SignatureVerification
{
    public class LowlevelCryptVerification : IValidateCadesSignature
    {
        /// <summary>
        /// https://habr.com/ru/articles/734368/
        /// </summary>
        /// <param name="signMessage"></param>
        /// <param name="data"></param>
        /// <param name="detachedSignature"></param>
        /// <returns></returns>
        /// <exception cref="CapiLiteCoreException"></exception>
        public unsafe SignatureValidationResult VerifySignature(byte[] signMessage, byte[]? data, CadesFormat signatureFormat)
        {
            var result = new SignatureValidationResult();
            nint hMsg = 0;
            bool detachedSignature = false;

            try
            {
                hMsg = Crypt32Helper.CryptMsgOpenToDecode(Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING,
                detachedSignature ? Constants.CMSG_DETACHED_FLAG : 0U, 0, 0, 0, 0);

                if (hMsg == 0)
                {
                    string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                    throw new CapiLiteCoreException($"Ошибка открытия криптографического сообщения для декодирования подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                }

                // load signed CMS
                fixed (byte* pSignMessage = signMessage)
                {
                    if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pSignMessage, (uint)signMessage.Length, true))
                    {
                        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка загрузки подписи: {error}",CapiLiteCoreErrors.InternalServerError);
                    }
                }

                if (detachedSignature)
                {
                    if (data == null)
                    {
                        throw new CapiLiteCoreException($"Для проверки не переданы исходные данные для подписи", CapiLiteCoreErrors.InternalServerError);
                    }

                    if (data.Length > 0)
                        // load source data
                        fixed (byte* pData = data)
                        {
                            if (!Crypt32Helper.CryptMsgUpdate(hMsg, (nint)pData, (uint)data.Length, true))
                            {
                                string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                                throw new CapiLiteCoreException($"Ошибка загрузки исходных данных: {error}", CapiLiteCoreErrors.InternalServerError);
                            }
                        }
                    else
                        throw new CapiLiteCoreException("Для отсоединенной подписи исходные данные должны быть переданы", CapiLiteCoreErrors.InternalServerError);
                }

                nint hCertStore = 0;
                nint hInfo = 0;
                try
                {
                    //извлечение сертификатов из системы
                    //uint dwFlags = Constants.CERT_SYSTEM_STORE_CURRENT_USER | Constants.CERT_STORE_READONLY_FLAG | Constants.CERT_STORE_OPEN_EXISTING_FLAG;//StoreLocation.CurrentUser, string pvPara
                    //hCertStore = Crypt32Helper.CertOpenStore(new IntPtr((int)Constants.CERT_STORE_PROV_SYSTEM_A), (uint)Constants.PKCS_7_OR_X509_ASN_ENCODING, 0, 
                    //    dwFlags, "My");//Marshal.StringToHGlobalAnsi("My")
                    //извлечение сертификатов из подписи в виде хранилища сертификатов
                    hCertStore = Crypt32Helper.CertOpenStore(Constants.CERT_STORE_PROV_MSG, 0, 0, 0, hMsg);

                    if (hCertStore == 0)
                    {
                        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка получения хранилища сертификатов: {error}", CapiLiteCoreErrors.InternalServerError);
                    }

                    // determine signer count
                    var signerCount = 0U;
                    var signerCountSize = Marshal.SizeOf(signerCount);
                    if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_COUNT_PARAM, 0, (nint)(&signerCount), ref signerCountSize))
                    {
                        string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                        throw new CapiLiteCoreException($"Ошибка получения подписывателей: {error}", CapiLiteCoreErrors.InternalServerError);
                    }

                    if (signerCount == 0)
                    {
                        throw new CapiLiteCoreException($"Ошибка подпись не содержит подписывателя", CapiLiteCoreErrors.InternalServerError);
                    }

                    // verify signature for every signer
                    for (var signerIndex = 0U; signerIndex < signerCount; signerIndex++)
                    {
                        #region вытаскивиние атрибутов подписи
                        var signerInfoSize = 0;
                        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, signerIndex, 0, ref signerInfoSize))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                        }
                        //todo: переделать выделение памяти
                        hInfo = Marshal.AllocHGlobal((int)signerInfoSize);
                        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_INFO_PARAM, signerIndex, hInfo, ref signerInfoSize))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                        }
                        var pSignerInfo = (CMSG_SIGNER_INFO?)Marshal.PtrToStructure(hInfo, typeof(CMSG_SIGNER_INFO));

                        if (pSignerInfo == null)
                        {
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата", CapiLiteCoreErrors.InternalServerError);
                        }

                        var fpSignedAttributes = ReadCryptoAttrsCollection(pSignerInfo.Value.AuthAttrs);
                        //string contentType = BytesToStringConverted(fpSignedAttributes[0].Values[0].RawData);
                        //string contentType = System.Text.Encoding.UTF8.GetString(fpSignedAttributes[0].Values[0].RawData);
                        //byte[] contentTypeData = Convert.FromBase64String(contentType);
                        //string contentTypeDecodedString = System.Text.Encoding.UTF8.GetString(contentTypeData);
                        //long longVar = BitConverter.ToInt64(fpSignedAttributes[1].Values[0].RawData, 0);
                        //DateTime dateTimeVar = new DateTime(1980, 1, 1).AddMilliseconds(longVar);

                        var signedInfoSize = 0;
                        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_ENCODED_MESSAGE, signerIndex, 0, ref signedInfoSize))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                        }
                        var vData = new byte[signedInfoSize];
                        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_ENCODED_MESSAGE, signerIndex, vData, ref signedInfoSize))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                        }
                        var signedCms = new SignedCms();
                        signedCms.Decode(vData);
                        foreach (var signerInfo in signedCms.SignerInfos)
                        {
                            foreach (var unsignedAttribute in signerInfo.UnsignedAttributes)
                            {
                                //if (unsignedAttribute.Oid.Value == WinCrypt.szOID_RSA_counterSign)
                                //{
                                //    //Note at this point we assume this counter signature is the timestamp
                                //    //refer to http://support.microsoft.com/kb/323809 for the origins

                                //    //TODO: extract timestamp value, if required
                                //    return true;
                                //}

                            }
                        }

                        //content-type:
                        var contentTypeSize = 0;
                        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_INNER_CONTENT_TYPE_PARAM, signerIndex, 0, ref contentTypeSize))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                        }
                        var contentTypeData = new byte[contentTypeSize];
                        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_INNER_CONTENT_TYPE_PARAM, signerIndex, contentTypeData, ref contentTypeSize))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}",CapiLiteCoreErrors.InternalServerError);
                        }
                        //string contentType = System.Text.Encoding.UTF8.GetString(contentTypeData);
                        #endregion


                        // extract CERT_ID
                        nint pCertContext = 0;
                        var certIdLength = 0;
                        if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_CERT_ID_PARAM, signerIndex, 0, ref certIdLength))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                        }

                        byte[] certIdRaw = ArrayPool<byte>.Shared.Rent(certIdLength);
                        try
                        {
                            fixed (byte* pCertId = certIdRaw)
                            {
                                if (!Crypt32Helper.CryptMsgGetParam(hMsg, Constants.CMSG_SIGNER_CERT_ID_PARAM, signerIndex, (nint)pCertId, ref certIdLength))
                                {
                                    string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                                    throw new CapiLiteCoreException($"Ошибка извлечения ID сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                                }

                                pCertContext = Crypt32Helper.CertFindCertificateInStore(hCertStore, Constants.X509_ASN_ENCODING | Constants.PKCS_7_ASN_ENCODING,
                                    0, Constants.CERT_FIND_CERT_ID, (nint)pCertId, 0);

                                if (pCertContext == 0)
                                {
                                    string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                                    throw new CapiLiteCoreException($"Ошибка извлечения сертификата из подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                                }
                            }
                        }
                        finally
                        {
                            ArrayPool<byte>.Shared.Return(certIdRaw, true);
                        }

                        var vsp = new CMSG_CTRL_VERIFY_SIGNATURE_EX_PARA();
                        vsp.cbSize = (uint)Marshal.SizeOf(vsp);
                        vsp.dwSignerIndex = signerIndex;
                        vsp.dwSignerType = Constants.CMSG_VERIFY_SIGNER_CERT;
                        vsp.pvSigner = pCertContext;

                        if (!Crypt32Helper.CryptMsgControl(hMsg, 0, Constants.CMSG_CTRL_VERIFY_SIGNATURE_EX, (nint)(&vsp)))
                        {
                            string error = Crypt32Helper.GetErrorDescription((uint)Kernel32Helper.GetLastError());
                            throw new CapiLiteCoreException($"Ошибка проверки подписи: {error}", CapiLiteCoreErrors.InternalServerError);
                        }

                        result.IsSignatureValid = true;
                    }
                }
                finally
                {
                    Crypt32Helper.CertCloseStore(hCertStore, Constants.CERT_CLOSE_STORE_FORCE_FLAG);
                    if (hInfo != IntPtr.Zero) Marshal.FreeHGlobal(hInfo);
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                throw;
            }
            finally
            {
                if (hMsg != 0) Crypt32Helper.CryptMsgClose(hMsg);
            }

            return result;
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
            var blob = (CRYPTOAPI_BLOB?)Marshal.PtrToStructure(pBlob, typeof(CRYPTOAPI_BLOB));

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
                    IntPtr pAttributeBlob = new IntPtr((long)_pAttr.rgValue + (i * Marshal.SizeOf(typeof(CRYPTOAPI_BLOB))));
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

        //private string BytesToStringConverted(byte[] bytes)
        //{
        //    string response = string.Empty;

        //    foreach (byte b in bytes)
        //        response += (Char)b;

        //    return response;
        //}
    }
}
