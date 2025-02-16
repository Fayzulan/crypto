namespace CryptoProWrapper
{
    public class DecryptionResult
    {
        /// <summary>
        /// Расшифрованные прошло успешно
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Расшифрованные данные
        /// </summary>
        public string Content { get; set; }

        /// <summary>
        /// Сообщение об ошибке
        /// </summary>
        public string Error { get; set; }
    }
}
