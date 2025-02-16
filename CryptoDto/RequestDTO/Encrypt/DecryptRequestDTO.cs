using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CryptoDto.RequestDTO.Encrypt
{
    /// <summary>
    /// DTO метода расшифрования
    /// </summary>
    public class DecryptRequetDTO : CryptoContainerRequestDto
    {
        /// <summary>
        /// хеш пинкода
        /// </summary>
        [Required(ErrorMessage = "\"PinHashCode\" пуст")]
        public string PinHashCode { get; set; }

        /// <summary>
        /// данные 
        /// </summary>
        [Required(ErrorMessage = "\"data\" пуст")]
        [JsonPropertyName("content")]
        public string Content { get; set; }
    }
}
