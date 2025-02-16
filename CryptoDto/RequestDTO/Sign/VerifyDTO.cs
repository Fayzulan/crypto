using System.ComponentModel.DataAnnotations;

namespace CryptoDto.RequestDTO.Sign
{
    /// <summary>
    /// DTO Метода валидации подписи 
    /// </summary>
    public class VerifyDTO : CryptoRequestDto
    {
#nullable disable
        /// <summary>
        /// Подписанный документ 
        /// </summary>
        [Required(ErrorMessage = "\"Подписанный документ\" пуст")]
        public string Signature { get; set; }
#nullable restore

        /// <summary>
        /// Исходный документ. Используется только для проверки отсоединенной подписи (в кодировке Base64)
        /// </summary>
        public string? Source { get; set; }

    }
}
