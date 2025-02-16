using CryptoDto.RequestDTO.Encrypt;
using CryptoProWrapper;

namespace CryptoAPI.Services
{
    public interface IEncryptionService
    {
        EncryptionResult Encrypt(EncryptRequetDTO encryptRequetDTO);

        DecryptionResult Decrypt(DecryptRequetDTO decryptRequetDTO);
    }
}
