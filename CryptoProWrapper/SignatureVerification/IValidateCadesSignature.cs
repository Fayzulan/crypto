namespace CryptoProWrapper.SignatureVerification
{
    public interface IValidateCadesSignature
    {
        SignatureValidationResult VerifySignature(byte[] signMessage, byte[]? data, CadesFormat signatureFormat);
    }
}
