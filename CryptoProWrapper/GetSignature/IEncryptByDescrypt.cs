namespace CryptoProWrapper
{
    public interface IEncryptByDescrypt
    {
        public unsafe SignatureCreateResult GetEncrypt(CryptoContainer container, string data);

        public unsafe SignatureCreateResult GetDecrypt(CryptoContainer container, string data);
    }
}