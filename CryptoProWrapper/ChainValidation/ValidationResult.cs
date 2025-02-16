namespace CryptoAPI
{
    public class ValidationResult
    {
        public string message;
        public int errorCode;
        public bool validationSucceed;
        public bool isValidated;

        public ValidationResult()
        {
            validationSucceed = true;
            message = "Цепочка валидна.";
            errorCode = 0;
        }
    }
}
