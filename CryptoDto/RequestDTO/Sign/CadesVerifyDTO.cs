using CryptoDto.Enums;
using System.ComponentModel.DataAnnotations;

namespace CryptoDto.RequestDTO.Sign
{
    /// <summary>
    /// DTO метода валидации Cades
    /// </summary>
    public class CadesVerifyDTO : VerifyDTO
    {
        /// <summary>
        /// Формат кадес 
        /// </summary>
        [Required(ErrorMessage = "\"Формат кадес\" пуст")]
        public APICadesFormat SignatureFormat { get; set; }
    }
}
