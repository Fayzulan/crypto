using System.Text.Json.Serialization;

namespace CryptoDto.ResponseDTO
{
    public class SignatureResponseDto : CryptoResponseDto
    {
        [JsonPropertyName("signature")]
        public byte[]? Signature { get; set; }
    }
}
