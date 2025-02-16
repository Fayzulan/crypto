using CryptoDto.Enums;
using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CryptoDto.RequestDTO.Encrypt
{
    /// <summary>
    /// DTO метода Шифрования
    /// </summary>
    public class EncryptRequetDTO : CryptoContainerRequestDto
    {
#nullable disable
        /// <summary>
        /// Данные для шифрования (в кодировке Base64)
        /// </summary>
        [Required(ErrorMessage = "\"Данные для шифрования (в кодировке Base64\" пуст")]
        [JsonPropertyName("data")]
        public string Data { get; set; }
#nullable restore

        /// <summary>
        /// OID алгоритма шифрования
        /// </summary>
        [Required(ErrorMessage = "\" OID алгоритма шифрования\" пуст")]
        [JsonPropertyName("encryptionAlgorithm")]
        public CEcryptionAlgorithm CEcryptionAlgorithm { get; set; }
    }
}
