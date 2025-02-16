using Crypto.Interfaces;
using CryptoProWrapper.Crypto.Entities;

namespace CryptoProWrapper.GetSignature
{
    public interface ISignaturePreparations
    {
        public byte[]? GetParentCertFromTheInternet(ICCertificate cert);
        public byte[]? GetCRLFromTheInternet(ICCertificate cert);
        public ICStore PrepareStores(DisposableCollection<ICCertificate> collection, ICRL? crl = null);
        public DisposableCollection<ICCertificate> PrepareCertCollection(ICCertificate signerCert);
    }
}
