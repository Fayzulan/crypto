using CryptoAPI.Services;
using CryptoDto.Enums;
using CryptoDto.RequestDTO.Sign;
using CryptoDto.ResponseDTO;
using CryptoProWrapper;
using Microsoft.AspNetCore.Mvc;

namespace CryptoAPI.Controllers.V2
{
    [ApiVersion("2.0")]
    [ApiController]
    [Route("[controller]")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public class SignatureController : ControllerBase
    {
        private readonly ISignatureService _signatureService;

        public SignatureController(ISignatureService signatureService, IEncryptionService encryptionService)
        {
            _signatureService = signatureService;
        }


        /// <remarks>
        /// Content даннные для подписи
        /// NameSign название подписи по которой мы будем искать сертификат // переименовать 
        /// ID системы 
        /// PinHashCode пинкод закрытого ключа
        /// signatureFormat формат
        /// IsDetached флаг отсоедененой подписи
        /// 
        ///   Пример ответа:
        ///   
        ///   {
        ///   
        ///   }
        /// 
        /// </remarks>

        /// Content даннные для подписи
        /// NameSign название подписи по которой мы будем искать сертификат // переименовать 
        /// ID системы 
        /// PinHashCode пинкод закрытого ключа
        /// signatureFormat формат
        /// IsDetached флаг отсоедененой подписи
        [HttpPost("SignCades")]
        public IActionResult SignCades(string Content,
            string NameSign, string PinHashCode,
            APICadesFormat signatureFormat = APICadesFormat.CadesBes,
            bool IsDetached = false)
        {
            try
            {
                byte[] ContentByteArray = Convert.FromBase64String(Content);

                var signatureCreateResult = _signatureService.SignCades(new SignCadesDTO
                {
                    Content = Content,
                    NameSign = NameSign,
                    PinHashCode = PinHashCode,
                    IsDetached = IsDetached,
                    SignatureFormat = signatureFormat,
                    OperationId = "OperationId1",
                    OperationPhaseId = "OperationPhaseId2",
                    projectCode = "test_project_сode",
                    SystemName = "test_stand_name"
                });

                if (signatureCreateResult.SignatureData == null)
                {
                    throw new CryptoAPIException("Подпись cades не получена", CryptoAPIErrors.NoContent);
                }

                var signature = new SignatureResponseDto
                {
                    Signature = signatureCreateResult.SignatureData,
                    Date = DateTime.UtcNow
                };
                return Ok(signature);
            }
            catch (Exception ex)
            {
                string logmsg = ex.Message;
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        [HttpPost("SignXades")]
        public IActionResult SignXades(string Content,
        string NameSign, string PinHashCode, APIXadesFormat signatureFormat,
        APIXadesType xadesType = APIXadesType.ENVELOPED)
        {
            try
            {
                var signatureCreateResult = _signatureService.SignXades(new SignXadesDTO
                {
                    Content = Content,
                    NameSign = NameSign,
                    PinHashCode = PinHashCode,
                    XadesType = xadesType,
                    SignatureFormat = signatureFormat,
                    OperationId = "OperationId1",
                    OperationPhaseId = "OperationPhaseId2",
                    projectCode = "test_project_сode",
                    SystemName = "test_stand_name"
                });

                if (signatureCreateResult.SignatureData == null)
                {
                    throw new CryptoAPIException("Подпись xades не получена", CryptoAPIErrors.NoContent);
                }

                var signature = new SignatureResponseDto
                {
                    Signature = signatureCreateResult.SignatureData,
                    Date = DateTime.UtcNow
                };
                return Ok(signature);
            }
            catch(CapiLiteCoreException)
            {
                throw;
            }
            catch (Exception ex)
            {
                string logmsg = ex.Message;
                return StatusCode(StatusCodes.Status500InternalServerError);
            }
        }

        /// <summary>
        /// метод проверки подписи 
        /// </summary>
        /// <param name="content">Подписанный документ или значение подписи для проверки (в кодировке Base64)</param>
        /// <param name="SignatureFormat"> Формат подписи.</param>
        /// <param name="isDetached">открепленная прикрепленная</param>
        /// <param name="source">Исходный документ. Используется только для проверки отсоединенной подписи (в кодировке Base64)</param>
        /// <returns></returns>
        [HttpPost("CadesVerify")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public IActionResult CadesVerify(string content, APICadesFormat SignatureFormat, bool isDetached, string source)
        {
            var signatureValidationResult = new SignatureValidationResult();
            string error = string.Empty;
            try
            {
                if (content.Length == 0)
                {
                    throw new CryptoAPIException("Не предоставлена подпись", CryptoAPIErrors.BadRequest);
                }

                if (source.Length == 0)
                {
                    throw new CryptoAPIException("Исходный документ", CryptoAPIErrors.BadRequest);
                }
                using (var memoryData = new MemoryStream())
                {
                    // Convert Base64 string to byte array
                    byte[] contentArrayByte = Convert.FromBase64String(content);

                    byte[]? sourceMessageArrayByte = string.IsNullOrEmpty(source) ? null : Convert.FromBase64String(source);
                    using (var memorySignature = new MemoryStream())
                    {
                        signatureValidationResult = _signatureService.ValidateCadesSignature(contentArrayByte, SignatureFormat, sourceMessageArrayByte);
                    }
                }

                var signatureResponseDto = new ValidateSignaureResponseDto
                {
                    Success = true,
                    ErrorDescription = error
                };

                if (!string.IsNullOrEmpty(error))
                {
                    signatureResponseDto.Success = false;
                }

                return Ok(signatureResponseDto);
            }
            catch (CryptoAPIException ex)
            {
                string logmsg1 = ex.Message;
                var result = new ValidateSignaureResponseDto
                {
                    Success = false,
                    ErrorDescription = ex.Message
                };

                return StatusCode(StatusCodes.Status500InternalServerError, result);
            }
            catch (Exception ex)
            {
                string logmsg2 = ex.Message;
                var result = new ValidateSignaureResponseDto
                {
                    Success = false,
                    ErrorDescription = "Ошибка проверки подписи"
                    ,
                    ErrorCode = ex.Message
                };
                return StatusCode(StatusCodes.Status500InternalServerError, result);
            }
        }

        /// <summary>
        /// метод проверки подписи 
        /// </summary>
        /// <param name="content">Подписанный документ или значение подписи для проверки (в кодировке Base64)</param>
        /// <param name="signatureFormat"> Формат подписи.</param>
        /// <param name="xadesType">Тип подписи</param>
        /// <param name="isDetached">открепленная прикрепленная</param>
        /// <param name="source">Исходный документ. Используется только для проверки отсоединенной подписи (в кодировке Base64)</param>
        /// <returns></returns>
        [HttpPost("XadesVerify")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status500InternalServerError)]
        public IActionResult XadesVerify(string content, APIXadesFormat signatureFormat, bool isDetached, string source,
        APIXadesType xadesType = APIXadesType.ENVELOPED)
        {
            var signatureValidationResult = new SignatureValidationResult();
            string error = string.Empty;
            try
            {
                if (content.Length == 0)
                {
                    throw new CryptoAPIException("Не предоставлена подпись", CryptoAPIErrors.BadRequest);
                }

                if (source.Length == 0)
                {
                    throw new CryptoAPIException("Исходный документ пуст", CryptoAPIErrors.BadRequest);
                }
                using (var memoryData = new MemoryStream())
                {
                    // Convert Base64 string to byte array
                    byte[] contentArrayByte = Convert.FromBase64String(content);

                    byte[]? sourceMessageArrayByte = string.IsNullOrEmpty(source) ? null : Convert.FromBase64String(source);
                    using (var memorySignature = new MemoryStream())
                    {
                        signatureValidationResult = _signatureService.ValidateXadesSignature(signMessage: contentArrayByte, signatureFormat: signatureFormat, sourceMessageArrayByte, xadesType);
                    }
                }

                var signatureResponseDto = new ValidateSignaureResponseDto
                {
                    Success = true,
                    ErrorDescription = error
                };

                if (!string.IsNullOrEmpty(error))
                {
                    signatureResponseDto.Success = false;
                }

                return Ok(signatureResponseDto);
            }
            catch (CryptoAPIException ex)
            {
                string logMsg1 = ex.Message;
                var result = new ValidateSignaureResponseDto
                {
                    Success = false,
                    ErrorDescription = ex.Message
                };

                return StatusCode(StatusCodes.Status500InternalServerError, result);
            }
            catch (Exception ex)
            {
                string logMsg2 = ex.Message;
                var result = new ValidateSignaureResponseDto
                {
                    Success = false,
                    ErrorDescription = "Ошибка проверки подписи",
                    ErrorCode = ex.Message
                };
                return StatusCode(StatusCodes.Status500InternalServerError, result);
            }
        }
    }
}

