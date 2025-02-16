using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CryptoDto.RequestDTO.Sign
{
    /// <summary>
    /// DTO для подписи формата Cades 
    /// </summary>
    public class SignDTO : CryptoContainerRequestDto
    {
#nullable disable
        /// <summary>
        /// содежримое на подпись
        /// </summary>
        [Required(ErrorMessage = "\"Content\" пуст")]
        [JsonPropertyName("content")]
        public string Content { get; set; }

        /// <summary>
        /// хеш пинкода
        /// </summary>
        [Required(ErrorMessage = "\"PinHashCode\" пуст")]
        public string PinHashCode { get; set; } = "9af15b336e6a9619928537df30b2e6a2376569fcf9d7e773eccede65606529a0";
#nullable restore
    }
}
