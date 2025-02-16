using CryptoDto.Enums;
using System.ComponentModel.DataAnnotations;

namespace CryptoDto.RequestDTO.Sign
{
    /// <summary>
    /// DTO метода валидации Xades
    /// </summary>
    public class XadesVerifyDTO : VerifyDTO
    {
        /// <summary>
        /// Формат подписи
        /// </summary>
        [Required(ErrorMessage = "\"Формат подписи\" пуст")]
        public APIXadesFormat SignatureFormat { get; set; }

        /// <summary>
        /// Тип подписи
        /// </summary>
        [Required(ErrorMessage = "\"Тип подписи\" пуст")]
        public APIXadesType XadesType { get; set; }
    }
}
