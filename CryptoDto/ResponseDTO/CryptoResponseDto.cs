using System.Text.Json.Serialization;

namespace CryptoDto.ResponseDTO
{
    public class CryptoResponseDto
    {
        /// <summary>
        /// Признак успешной операции
        /// </summary>
        [JsonPropertyName("success")]
        public bool Success { get; set; } = true;

        /// <summary>
        /// Дата/время операции
        /// </summary>
        [JsonPropertyName("date")]
        public DateTime Date { get; set; }

        /// <summary>
        /// Код ошибки в случае неуспешного выполнения операции
        /// </summary>
        [JsonPropertyName("errorCode")]
        public string? ErrorCode { get; set; }

        /// <summary>
        /// Описание ошибки в случае неуспешного выполнения операции
        /// </summary>
        [JsonPropertyName("errorDescription")]
        public string? ErrorDescription { get; set; }
    }
}
