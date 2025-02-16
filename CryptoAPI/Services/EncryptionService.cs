using CryptoDto.Enums;
using CryptoDto.RequestDTO.Encrypt;
using CryptoProWrapper;
using CryptStructure;

namespace CryptoAPI.Services
{
    /// <summary>
    /// Сервис шифрации дешифрапции 
    /// </summary>
    public class EncryptionService : CryptoService, IEncryptionService
    {
        private readonly IEncryptionMessageService _encryptionMessageService;

        /// <summary>
        /// .ctor
        /// </summary>
        /// <param name="encryptionMessageService"></param>
        /// <param name="vaultIntegrationDataService"></param>
        /// <param name="logRecordService"></param>
        /// <param name="cryptoServiceLogRecordService"></param>
        /// <param name="requestInfo"></param>
        public EncryptionService(
            IEncryptionMessageService encryptionMessageService) : base()
        {
            _encryptionMessageService = encryptionMessageService;
        }

        /// <summary>
        /// метод шифрования
        /// </summary>
        /// <param name="encryptRequetDTO"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public EncryptionResult Encrypt(EncryptRequetDTO encryptRequetDTO)
        {
            var ecnryptionResult = new EncryptionResult();
            try
            {
                byte[] DataByteArray = Convert.FromBase64String(encryptRequetDTO.Data);
                string encryptionAlgorythmOid = string.Empty;
                CryptoContainer container = GetContainer(encryptRequetDTO);

                switch (encryptRequetDTO.CEcryptionAlgorithm)
                {
                    case CEcryptionAlgorithm.Gost28147:
                        encryptionAlgorythmOid = Constants.szOID_CP_GOST_28147;
                        break;
                    default:
                        throw new NotImplementedException();
                }

                ecnryptionResult = _encryptionMessageService.EncryptMessage(container, DataByteArray, encryptionAlgorythmOid);

                return ecnryptionResult;
            }
            catch (CryptoAPIException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw;
            }
        }

        public DecryptionResult Decrypt(DecryptRequetDTO decryptRequetDTO)
        {
            var decryptionResult = new DecryptionResult();
            try
            {
                byte[] DataByteArray = Convert.FromBase64String(decryptRequetDTO.Content);
                CryptoContainer container = GetContainer(decryptRequetDTO, true, decryptRequetDTO.PinHashCode);
                decryptionResult = _encryptionMessageService.DecryptMessage(container, DataByteArray);

                return decryptionResult;
            }
            catch (CryptoAPIException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logMsg1 = ex.Message;
                throw;
            }
        }
    }
}
