using CryptoAPI.Services;
using CryptoDto.RequestDTO.Encrypt;
using CryptoDto.ResponseDTO;
using Microsoft.AspNetCore.Mvc;

namespace CryptoAPI.Controllers.V1
{
    [ApiController]
    [ApiVersion("1.0")]
    [Route("[controller]")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public class EncryptionController : CryptoController
    {
        private readonly IEncryptionService _encryptionService;

        public EncryptionController(
            IConfiguration config,
            IEncryptionService encryptionService) : base(config)
        {
            _encryptionService = encryptionService;
        }

        [HttpPost("Encrypt")]
        [ProducesResponseType(typeof(EncryptedResponseDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public ActionResult<EncryptedResponseDto> Encrypt(EncryptRequetDTO encryptRequetDTO)
        {
            string logMsg1 = $"Запрос шифрования: projectCode = {encryptRequetDTO.projectCode}, SystemName = {encryptRequetDTO.SystemName}, NameSign = {encryptRequetDTO.NameSign}, CEcryptionAlgorithm = {encryptRequetDTO.CEcryptionAlgorithm}";

            var res = new EncryptedResponseDto();
            try
            {
                Span<byte> contentBuffer = new Span<byte>(new byte[encryptRequetDTO.Data.Length]);

                if (!Convert.TryFromBase64String(encryptRequetDTO.Data, contentBuffer, out int bytesParsed))
                {
                    throw new CryptoAPIException("Данные, которые необходимо подписать, имеют не верный формат.", CryptoAPIErrors.BadRequest);
                }

                byte[] DataByteArray = Convert.FromBase64String(encryptRequetDTO.Data);
                var encryptionResult = _encryptionService.Encrypt(encryptRequetDTO);
                res.Result = encryptionResult.EncryptedData;
                res.Date = DateTime.UtcNow;
                res.ErrorDescription = encryptionResult.Error;
                res.Success = encryptionResult.Success;               
            }
            catch (Exception ex)
            {
                string logMsg2 = ex.Message;
                throw;
            }

            string logMsg3 = $"Ответ на запрос шифрования: Date = {res.Date}, Success = {res.Success}, ErrorDescription = {res.ErrorDescription}";
            return Ok(res);
        }

        [HttpPost("Decrypt")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public IActionResult Decrypt(DecryptRequetDTO decryptRequetDTO)
        {
            string logMsg1 = $"Запрос расшифровки: projectCode = {decryptRequetDTO.projectCode}, SystemName = {decryptRequetDTO.SystemName}, NameSign = {decryptRequetDTO.NameSign}";

            var res = new DecryptedResponseDto();
            try
            {
                Span<byte> contentBuffer = new Span<byte>(new byte[decryptRequetDTO.Content.Length]);

                if (!Convert.TryFromBase64String(decryptRequetDTO.Content, contentBuffer, out int bytesParsed))
                {
                    throw new CryptoAPIException("Данные, которые необходимо подписать, имеют не верный формат.", CryptoAPIErrors.BadRequest);
                }

                var decryptionResult = _encryptionService.Decrypt(decryptRequetDTO);
                res.decryptedContent = decryptionResult.Content;
                res.Date = DateTime.UtcNow;
                res.ErrorDescription = decryptionResult.Error;
                res.Success = decryptionResult.Success;
            }
            catch (Exception ex)
            {
                string logMsg2 = ex.Message;
                throw;
            }

            string logMsg3 = $"Ответ на запрос расшифровки: Date = {res.Date}, Success = {res.Success}, ErrorDescription = {res.ErrorDescription}";
            return Ok(res);
        }
    }
}
