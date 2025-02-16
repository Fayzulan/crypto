namespace CryptoAPI
{
    public class AuthorizeException : Exception
    {
        /// <summary>
        /// Код ошибки (200+)
        /// </summary>
        public AuthorizeErrors ErrorCode { get; set; }
        public AuthorizeException(string message, AuthorizeErrors ErrorCode) : base(message)
        {
            this.ErrorCode = ErrorCode;
        }
    }
}
