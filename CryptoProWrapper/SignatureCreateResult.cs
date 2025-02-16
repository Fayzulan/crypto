namespace CryptoProWrapper
{
    /// <summary>
    /// Результат создания подписи
    /// </summary>
    public class SignatureCreateResult
    {
        /// <summary>
        /// Подпись успешно создана
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Подпись
        /// </summary>
        public byte[]? SignatureData { get; set; }

        /// <summary>
        /// Сообщение об ошибке
        /// </summary>
        public string Error { get; set; }
    }
}
