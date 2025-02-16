using CryptoAPI.Services;
using CryptoDto.RequestDTO;
using CryptoDto.RequestDTO.Sign;
using CryptoDto.ResponseDTO;
using CryptoProWrapper;
using Microsoft.AspNetCore.Mvc;

namespace CryptoAPI.Controllers.V1
{
    [ApiController]
    [Route("[controller]")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public class SignatureController : CryptoController
    {
        private readonly ISignatureService _signatureService;

        public SignatureController(ISignatureService signatureService, IConfiguration config) : base(config)
        {
            _signatureService = signatureService;
        }

        /// <summary>
        /// Запрос на получение подписанного сообщения формата CADES
        /// </summary>     
        [HttpPost("SignCades")]
        public IActionResult SignCades(SignCadesDTO signCadesDTO)
        {
            try
            {
                string logMsg1 = $"Запрос на получение подписанного сообщения формата CADES: {SerializeSignDTO(signCadesDTO)}, NameSign = {signCadesDTO.NameSign}, SignatureFormat={signCadesDTO.SignatureFormat}, IsDetached={signCadesDTO.IsDetached}";
                Span<byte> contentBuffer = new Span<byte>(new byte[signCadesDTO.Content.Length]);

                if (!Convert.TryFromBase64String(signCadesDTO.Content, contentBuffer, out int bytesParsed))
                {
                    throw new CryptoAPIException("Данные, которые необходимо подписать, имеют не верный формат.", CryptoAPIErrors.BadRequest);
                }

                var signatureCreateResult = _signatureService.SignCades(signCadesDTO);
                var signature = new SignatureResponseDto
                {
                    Signature = signatureCreateResult.SignatureData,
                    Date = DateTime.UtcNow,
                    Success = signatureCreateResult.Success,
                    ErrorDescription = signatureCreateResult.Error
                };
                string logMsg2 = $"Ответ на запрос на получение подписанного сообщения формата CADES: {SerializeCryptoResponseDto(signature)}";
                return Ok(signature);
            }
            catch (Exception ex)
            {
                string logMsg3 = ex.Message;
                throw;
            }
        }

        /// <summary>
        /// Запрос на получение подписанного сообщения формата XADES
        /// </summary>
        [HttpPost("SignXades")]
        public IActionResult SignXades(SignXadesDTO signXadesDTO)
        {
            try
            {
                string logMsg1 = $"Запрос на получение подписанного сообщения формата XADES: {SerializeSignDTO(signXadesDTO)}, NameSign = {signXadesDTO.NameSign}, SignatureFormat={signXadesDTO.SignatureFormat}, XadesType={signXadesDTO.XadesType}";
                Span<byte> contentBuffer = new Span<byte>(new byte[signXadesDTO.Content.Length]);

                if (!Convert.TryFromBase64String(signXadesDTO.Content, contentBuffer, out int bytesParsed))
                {
                    throw new CryptoAPIException("Данные, которые необходимо подписать, имеют не верный формат.", CryptoAPIErrors.BadRequest);
                }

                var signatureCreateResult = _signatureService.SignXades(signXadesDTO);
                var signature = new SignatureResponseDto
                {
                    Signature = signatureCreateResult.SignatureData,
                    Date = DateTime.UtcNow,
                    Success = signatureCreateResult.Success,
                    ErrorDescription = signatureCreateResult.Error
                };
                string logMsg2 = $"Ответ на запрос на получение подписанного сообщения формата XADES: {SerializeCryptoResponseDto(signature)}";
                return Ok(signature);
            }
            catch (Exception ex)
            {
                string logMsg3 = ex.Message;
                throw;
            }
        }

        /// <summary>
        /// Запрос на проверку подписанного сообщения формата CADES
        /// </summary>
        /// <param name="cadesVerifyDTO"></param>
        /// <returns></returns>
        [HttpPost("CadesVerify")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public IActionResult CadesVerify(CadesVerifyDTO cadesVerifyDTO)
        {
            var signatureValidationResult = new SignatureValidationResult();
            string error = string.Empty;
            try
            {
                string logMsg1 = $"Запрос на проверку подписанного сообщения формата CADES: {SerializeSignDTO(cadesVerifyDTO)}, SignatureFormat={cadesVerifyDTO.SignatureFormat}";
                using (var memoryData = new MemoryStream())
                {
                    // Convert Base64 string to byte array
                    byte[] contentArrayByte = Convert.FromBase64String(cadesVerifyDTO.Signature);

                    byte[]? sourceMessageArrayByte = string.IsNullOrEmpty(cadesVerifyDTO.Source) ? null : Convert.FromBase64String(cadesVerifyDTO.Source);
                    using (var memorySignature = new MemoryStream())
                    {
                        signatureValidationResult = _signatureService.ValidateCadesSignature(contentArrayByte, cadesVerifyDTO.SignatureFormat, sourceMessageArrayByte);
                    }
                }

                var validateSignaureResponseDto = new ValidateSignaureResponseDto
                {
                    Date = DateTime.UtcNow,
                    Success = true,
                    ErrorDescription = signatureValidationResult.Error,
                    Result = signatureValidationResult.IsSignatureValid,
                };
                string logMsg2 = $"Ответ на запрос на проверку подписанного сообщения формата CADES: {SerializeCryptoResponseDto(validateSignaureResponseDto)}, Result={validateSignaureResponseDto.Result}";
                return Ok(validateSignaureResponseDto);
            }
            catch (Exception ex)
            {
                string logMsg3 = ex.Message;
                throw;
            }
        }

        /// <summary>
        /// Запрос на проверку подписанного сообщения формата XADES 
        /// </summary>
        /// <param name="xadesVerifyDTO">Подписанный документ или значение подписи для проверки (в кодировке Base64)</param>
        /// <returns></returns>
        [HttpPost("XadesVerify")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public IActionResult XadesVerify(XadesVerifyDTO xadesVerifyDTO)
        {
            var signatureValidationResult = new SignatureValidationResult();
            try
            {
                string logMsg1 = $"Запрос на проверку подписанного сообщения формата XADES: {SerializeSignDTO(xadesVerifyDTO)}, SignatureFormat={xadesVerifyDTO.SignatureFormat}, XadesType={xadesVerifyDTO.XadesType}";
                using (var memoryData = new MemoryStream())
                {
                    // Convert Base64 string to byte array
                    byte[] contentArrayByte = Convert.FromBase64String(xadesVerifyDTO.Signature);

                    byte[]? sourceMessageArrayByte = string.IsNullOrEmpty(xadesVerifyDTO.Source) ? null : Convert.FromBase64String(xadesVerifyDTO.Source);
                    using (var memorySignature = new MemoryStream())
                    {
                        signatureValidationResult = _signatureService.ValidateXadesSignature(signMessage: contentArrayByte, signatureFormat: xadesVerifyDTO.SignatureFormat, sourceMessageArrayByte, xadesVerifyDTO.XadesType);
                    }
                }

                var signatureResponseDto = new ValidateSignaureResponseDto
                {
                    Success = true,
                    ErrorDescription = signatureValidationResult.Error,
                    Result = signatureValidationResult.IsSignatureValid,
                    Date = DateTime.Now
                };

                if (!string.IsNullOrEmpty(signatureValidationResult.Error))
                {
                    signatureResponseDto.Success = false;
                }

                string logMsg2 = $"Ответ на запрос на проверку подписанного сообщения формата XADES: {SerializeCryptoResponseDto(signatureResponseDto)}, Result={signatureResponseDto.Result}";
                return Ok(signatureResponseDto);
            }
            catch (Exception ex)
            {
                string logMsg3 = ex.Message;
                throw;
            }
        }

        private string SerializeSignDTO(CryptoRequestDto dto)
        {
            return $"projectCode = {dto.projectCode}, SystemName = {dto.SystemName}, OperationId = {dto.OperationId}, OperationPhaseId = {dto.OperationPhaseId}";
        }

        private string SerializeCryptoResponseDto(CryptoResponseDto dto)
        {
            return $"Success = {dto.Success}, Date = {dto.Date}, ErrorCode = {dto.ErrorCode}, ErrorDescription = {dto.ErrorDescription}";
        }
    }
}

