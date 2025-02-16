namespace CryptoProWrapper.GetSignature
{
    public interface IGetXadesSignature
    {
        SignatureCreateResult GetXadesSignature(CryptoContainer container, byte[] data, XadesType xadesType, XadesFormat signatureFormat);
    }
}
