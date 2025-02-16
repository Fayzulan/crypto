namespace CryptoAPI
{
    public class CryptoAPIException : Exception
    {
        /// <summary>
        /// Код ошибки (100+)
        /// </summary>
        public CryptoAPIErrors ErrorCode { get; set; }
        public CryptoAPIException(string message, CryptoAPIErrors ErrorCode) : base(message)
        {
            this.ErrorCode = ErrorCode;
        }
    }
}
