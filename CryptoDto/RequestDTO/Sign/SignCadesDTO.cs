using CryptoDto.Enums;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CryptoDto.RequestDTO.Sign
{
    /// <summary>
    /// DTO для подписи формата Cades 
    /// </summary>
    public class SignCadesDTO : SignDTO
    {
        /// <summary>
        /// Формат подписи
        /// </summary>
        [Required(ErrorMessage = "\"Формат подписи\" пуст")]
        [JsonPropertyName("signatureFormat")]
        public APICadesFormat SignatureFormat { get; set; }

        /// <summary>
        /// Флаг отсоединенной подписи
        /// </summary>
        [Required(ErrorMessage = "\"Флаг отсоединенной подписи\" пуст")]
        [JsonPropertyName("isDetached")]
        public bool IsDetached { get; set; }
    }
}
