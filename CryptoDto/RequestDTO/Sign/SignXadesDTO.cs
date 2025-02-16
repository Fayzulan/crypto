using CryptoDto.Enums;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CryptoDto.RequestDTO.Sign
{
    /// <summary>
    /// DTO Метода подписи Xades
    /// </summary>
    public class SignXadesDTO : SignDTO
    {
        /// <summary>
        /// Формат подписи
        /// </summary>
        [Required(ErrorMessage = "\"Формат подписи\" пуст")]
        [JsonPropertyName("signatureFormat")]
        public APIXadesFormat SignatureFormat { get; set; }

        /// <summary>
        /// Тип подписи. 
        /// </summary>
        [Required(ErrorMessage = "\"Тип подписи\" пуст")]
        [JsonPropertyName("xadesType")]
        public APIXadesType XadesType { get; set; }
    }
}
