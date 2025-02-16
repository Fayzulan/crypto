using CryptoProWrapper;

namespace CryptoAPI.Services
{
    public interface IEncryptionMessageService
    {
        EncryptionResult EncryptMessage(CryptoContainer conteiner, byte[] data, string encryptionAlgorythmOid);

        DecryptionResult DecryptMessage(CryptoContainer conteiner, byte[] data);
    }
}
