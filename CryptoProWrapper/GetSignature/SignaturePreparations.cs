using Crypto.Entities;
using Crypto.Interfaces;
using Crypto.Pivot;
using CryptoProWrapper.Crypto.Entities;
using Microsoft.Extensions.Logging;

namespace CryptoProWrapper.GetSignature
{
    public class SignaturePreparations : ISignaturePreparations
    {
        private readonly IHttpClientFactory _httpClientFactory;

        public SignaturePreparations(IHttpClientFactory httpClientFactory)
        {
            _httpClientFactory = httpClientFactory;
        }

        public int GetParentFromCollection(DisposableCollection<ICCertificate> collection, ICCertificate cert)
        {
            for (int i = 0; i < collection.Count(); i++)
            {
                if (collection[i].IsParentFor(cert))
                {
                    return i;
                }
            }

            return -1;
        }

       /// <summary>
       /// Получает по ссылке родительский сертификат
       /// </summary>
       /// <param name="cert"></param>
       /// <returns></returns>
        public byte[]? GetParentCertFromTheInternet(ICCertificate cert)
        {
            if (string.IsNullOrEmpty(cert.issuerCertURL) || cert.isSelfSigned)
            {
                return null;
            }

            try
            {
                var client = _httpClientFactory.CreateClient();
                var certBytes = client.GetByteArrayAsync(new Uri(cert.issuerCertURL)).GetAwaiter().GetResult();

                return certBytes;
            }
            catch (Exception ex)
            {
                string logMsg1 = $"Ошибка получения по ссылке родительского сертификата: {ex.Message}";
            }

            return null;
        }

        public byte[]? GetCRLFromTheInternet(ICCertificate cert)
        {
            if (cert.crlURL == string.Empty)
            {
                return null;
            }

            var client = _httpClientFactory.CreateClient();
            var crlBytes = client.GetByteArrayAsync(new Uri(cert.crlURL)).Result;

            return crlBytes;
        }

        public ICStore PrepareStores(DisposableCollection<ICCertificate> collection, ICRL? crl = null)
        {
            var memoryStore = new CStore();

            try
            {
                memoryStore.Open(StoreType.Memory);

                foreach (var item in collection)
                {
                    memoryStore.Add(item);
                }

                if (crl != null)
                {
                    memoryStore.AddCRL(crl);
                }

                var numOfCertsInChain = collection.Count();

                if (numOfCertsInChain < 2)
                {
                    return memoryStore;
                    //throw new CapiLiteCoreException("Не удалось загрузить сертификаты цепочки либо сертификат самоподписанный");
                }

                var root = collection[collection.Count() - 1];

                if (root != null)
                {
                    using var systemStore = new CStore();
                    systemStore.OpenSystem(StoreNameType.Root);

                    systemStore.Add(root);
                }
            }
            catch (Exception ex)
            {
                memoryStore.Dispose();
                string logMsg1 = $"Произошла ошибка при подготовке хранилищ сертификатов для подписей: {ex.Message}";
                throw new CapiLiteCoreException($"Произошла ошибка при подготовке хранилищ сертификатов для подписей: {ex.Message}", CapiLiteCoreErrors.IntegrationTSPError);
            }

            return memoryStore;
        }

        public DisposableCollection<ICCertificate> PrepareCertCollection(ICCertificate signerCert)
        {
            var certCollection = new DisposableCollection<ICCertificate>();
            certCollection.AddElem(signerCert);

            var parentCertBytes = new byte[0];
            var childCertIndex = 0;

            while (parentCertBytes != null && childCertIndex < 100)
            {
                parentCertBytes = GetParentCertFromTheInternet(certCollection[childCertIndex]);
                if (parentCertBytes != null)
                {
                    var parentCert = new CCertificate(parentCertBytes);
                    certCollection.AddElem(parentCert);
                }
                childCertIndex++;
            }

            return certCollection;
        }
    }
}
