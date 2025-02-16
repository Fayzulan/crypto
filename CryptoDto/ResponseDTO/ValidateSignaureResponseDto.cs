using System.Text.Json.Serialization;

namespace CryptoDto.ResponseDTO
{
    public class ValidateSignaureResponseDto : CryptoResponseDto
    {
        /// <summary>
        /// Результат проверки подписи
        /// </summary>
        [JsonPropertyName("result")]
        public bool Result { get; set; }
    }
}
