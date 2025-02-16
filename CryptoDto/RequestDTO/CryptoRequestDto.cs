using System.ComponentModel.DataAnnotations;
using System.Text.Json.Serialization;

namespace CryptoDto.RequestDTO
{
    public class CryptoRequestDto
    {
        /// <summary>
        /// Идентификатор бизнес-операции
        /// </summary>
        [JsonPropertyName("operation_id")]
        public string? OperationId { get; set; }

        /// <summary>
        /// Идентификатор этапа бизнес-операции
        /// </summary>
        [JsonPropertyName("operation_phase_id")]
        public string? OperationPhaseId { get; set; }

        /// <summary>
        /// project_сode
        /// </summary>
        [JsonPropertyName("project_сode")]
        [Required(ErrorMessage = "\"project_сode\" пуст")]
        public string projectCode { get; set; }
        /// <summary>
        /// stand_name
        /// </summary>
        [JsonPropertyName("stand_name")]
        [Required(ErrorMessage = "\"stand_name\" пуст")]
        public string SystemName { get; set; }        
    }
}
