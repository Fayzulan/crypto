using System.Text.Json.Serialization;

namespace CryptoDto.ResponseDTO
{
    public class EncryptedResponseDto : CryptoResponseDto
    {
        [JsonPropertyName("result")]
        public byte[]? Result { get; set; }
    }
}
