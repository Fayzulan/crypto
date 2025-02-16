using CryptoAPI.Services;
using CryptoDto.Enums;
using CryptoDto.ResponseDTO;
using CryptoProWrapper;
using Microsoft.AspNetCore.Mvc;

namespace CryptoAPI.Controllers
{
    [ApiController]
    public class DevController : ControllerBase
    {
        private readonly ISignatureService _signatureService;

        public DevController(ISignatureService signatureService, IEncryptionService encryptionService)
        {
            _signatureService = signatureService;
        }
        /// <summary>
        /// метод для разработчиков 
        /// </summary>
        [HttpGet("Test1SignGET")]

        public void Test1SignGET()
        {
              throw new CryptoAPIException("Не предоставлен файл для подписи", CryptoAPIErrors.BadRequest);
        }
        /// <summary>
        /// метод для разработчиков 
        /// </summary>
        [HttpPost("XadesSignFile")]
        public SignatureResponseDto XadesSignFile(IFormFile file, APIXadesFormat signatureFormat, APIXadesType xadesType = APIXadesType.ENVELOPED)
        {
            var signatureCreateResult = new SignatureCreateResult();

            try
            {
                if (file.Length == 0)
                {
                    throw new CryptoAPIException("Не предоставлен файл для подписи", CryptoAPIErrors.BadRequest);
                }

                using (var ms = new MemoryStream())
                {
                    file.CopyTo(ms);
                    signatureCreateResult = _signatureService.TestSignXades(ms.ToArray(), xadesType, signatureFormat);
                }

                if (signatureCreateResult.SignatureData == null)
                {
                    throw new CryptoAPIException("Не получена подпись xades", CryptoAPIErrors.NoContent);
                }

                return new SignatureResponseDto
                {
                    Signature = signatureCreateResult.SignatureData
                };
            }
            catch (CryptoAPIException ex)
            {
                return new SignatureResponseDto
                {
                    Success = false,
                    ErrorDescription = ex.Message
                };
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка XadesSignFile: {ex.Message}");
                return new SignatureResponseDto
                {
                    Success = false,
                    ErrorDescription = "Ошибка подписи файла"
                };
            }
        }

        /// <summary>
        /// метод для разработчиков 
        /// </summary>
        [HttpPost("CadesSignFile")]
        public SignatureResponseDto CadesSignFile(IFormFile file, APICadesFormat signatureFormat, bool detachedSignature = false)
        {
            var signatureCreateResult = new SignatureCreateResult();

            try
            {
                if (file.Length == 0)
                {
                    throw new CryptoAPIException("Не предоставлен файл для подписи", CryptoAPIErrors.BadRequest);
                }

                using (var ms = new MemoryStream())
                {
                    file.CopyTo(ms);
                    var source = ms.ToArray();
                    signatureCreateResult = _signatureService.TestSignCades(source, detachedSignature, signatureFormat);

                    if (signatureCreateResult.SignatureData != null)
                    {
                        var signatureValidationResult = _signatureService.ValidateCadesSignature(signatureCreateResult.SignatureData, signatureFormat, source);
                    }
                }

                if (signatureCreateResult.SignatureData == null)
                {
                    throw new CryptoAPIException("Не удалось получить подпись", CryptoAPIErrors.BadRequest);
                }

                return new SignatureResponseDto
                {
                    Signature = signatureCreateResult.SignatureData
                };
            }
          
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка CadesSignFile: {ex.Message}");
                return new SignatureResponseDto
                {
                    Success = false,
                    ErrorDescription = "Ошибка подписи файла"
                };
            }
        }
    }
}
