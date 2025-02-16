namespace CryptoProWrapper.GetSign
{
    public interface IGetCadesSignature
    {
        List<KeyContainer> GetAllKeyContainers();
        SignatureCreateResult GetCadesBesSignature(CryptoContainer container, byte[] data, bool detachedSignature, bool includeCrl);
        void EnchanceSignature(SignatureCreateResult signature, CadesFormat signatureFormat);

        void DisplayAttachedSignature(byte[] sig);
        void DisplayDetachedSignature(byte[] sig);
    }
}
