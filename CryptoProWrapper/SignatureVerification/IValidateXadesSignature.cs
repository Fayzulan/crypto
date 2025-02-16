namespace CryptoProWrapper.SignatureVerification
{
    public interface IValidateXadesSignature
    {
        SignatureValidationResult VerifySignature(byte[] signMessage, byte[]? data, XadesFormat signatureFormat);
    }
}
