using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CryptoDto.RequestDTO
{
    public class CryptoContainerRequestDto: CryptoRequestDto
    {
        /// <summary>
        /// Название ключа
        /// </summary>        
        [JsonPropertyName("nameSign")]
        [Required(ErrorMessage = "\"NameSign\" пуст")]
        public string NameSign { get; set; }
    }
}
