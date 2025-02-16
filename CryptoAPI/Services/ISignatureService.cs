using CryptoDto.Enums;
using CryptoDto.RequestDTO.Sign;
using CryptoProWrapper;

namespace CryptoAPI.Services
{
    public interface ISignatureService
    {
        /// <summary>
        /// Получение подписи CADES
        /// </summary>
        /// <param name="signCadesDTO"></param>
        /// <returns></returns>
        SignatureCreateResult SignCades(SignCadesDTO signCadesDTO);

        /// <summary>
        /// Получение подписи XADES
        /// </summary>
        /// <param name="signXadesDTO"></param>
        /// <returns></returns>
        SignatureCreateResult SignXades(SignXadesDTO signXadesDTO);

        /// <summary>
        /// Проверка подписи CADES
        /// </summary>
        /// <param name="signMessage">подписанный документ (обязательный)</param>
        /// <param name="signatureFormat"></param>
        /// <param name="sourceMessage">оригинальный документ</param>
        /// <returns></returns>
        SignatureValidationResult ValidateCadesSignature(byte[] signMessage, APICadesFormat signatureFormat, byte[]? sourceMessage);

        /// <summary>
        /// Проверка подписи CADES
        /// </summary>
        /// <param name="signMessage">подписанный документ (обязательный)</param>
        /// <param name="signatureFormat"></param>
        /// <param name="sourceMessage">оригинальный документ</param>
        /// <param name="xadesType"></param>
        /// <returns></returns>
        SignatureValidationResult ValidateXadesSignature(byte[] signMessage, APIXadesFormat signatureFormat, byte[]? sourceMessage, APIXadesType xadesType);

        SignatureCreateResult TestSignCades(byte[] data, bool detachedSignature, APICadesFormat apiSignatureFormat);

        SignatureCreateResult TestSignXades(byte[] data, APIXadesType xadesType, APIXadesFormat signatureFormat);

        List<KeyContainer> GetAllKeyContainers();
    }
}
