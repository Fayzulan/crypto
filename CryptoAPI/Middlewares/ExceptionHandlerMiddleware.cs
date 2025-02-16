using CryptoDto.ResponseDTO;
using CryptoProWrapper;
using Newtonsoft.Json;
using System.Net;

namespace CryptoAPI.Middlewares
{

    /// <summary>
    /// Слой мидел варе для обработки ошибок 
    /// </summary>
    public class ExceptionHandlerMiddleware
    {
        private readonly RequestDelegate _next;

        public ExceptionHandlerMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task Invoke(HttpContext context)
        {
            try
            {
                await _next.Invoke(context);
            }
            catch (Exception ex)
            {
                await HandleExceptionMessageAsync(context, ex).ConfigureAwait(false);
            }
        }
        private static Task HandleExceptionMessageAsync(HttpContext context, Exception exception)
        {
            var httpStatusCode = (int)HttpStatusCode.InternalServerError;
            int ErrorCodeCrypto = 500;
            exception = exception.GetOriginalException();
            CryptoAPIException? cryptoAPIException = exception as CryptoAPIException;

            if (cryptoAPIException != null)
            {
                ErrorCodeCrypto = (int)cryptoAPIException.ErrorCode;
                httpStatusCode = cryptoAPIException.ErrorCode == CryptoAPIErrors.BadRequest ? (int)HttpStatusCode.BadRequest : httpStatusCode;
                httpStatusCode = cryptoAPIException.ErrorCode == CryptoAPIErrors.Unauthorized ? (int)HttpStatusCode.Unauthorized : httpStatusCode;
                httpStatusCode = cryptoAPIException.ErrorCode == CryptoAPIErrors.Forbidden ? (int)HttpStatusCode.Forbidden : httpStatusCode;
                httpStatusCode = cryptoAPIException.ErrorCode == CryptoAPIErrors.NoContent ? (int)HttpStatusCode.InternalServerError : httpStatusCode;
            }

            CapiLiteCoreException? capiLiteCoreException = exception as CapiLiteCoreException;

            if (capiLiteCoreException != null)
            {
                ErrorCodeCrypto = (int)capiLiteCoreException.ErrorCode;
                httpStatusCode = capiLiteCoreException.ErrorCode == CapiLiteCoreErrors.IntegrationTSPError ? (int)HttpStatusCode.InternalServerError : httpStatusCode;
                httpStatusCode = capiLiteCoreException.ErrorCode == CapiLiteCoreErrors.NotFaundCertificate ? (int)HttpStatusCode.NotFound : httpStatusCode;
                httpStatusCode = capiLiteCoreException.ErrorCode == CapiLiteCoreErrors.IntegrationTSPError ? (int)HttpStatusCode.InternalServerError : httpStatusCode;
                httpStatusCode = capiLiteCoreException.ErrorCode == CapiLiteCoreErrors.BadRequest ? (int)HttpStatusCode.BadRequest : httpStatusCode;
            }

            AuthorizeException? authorizeException = exception as AuthorizeException;

            if (authorizeException != null)
            {
                ErrorCodeCrypto = (int)authorizeException.ErrorCode;

                httpStatusCode = authorizeException.ErrorCode == AuthorizeErrors.BadRequest ? (int)HttpStatusCode.BadRequest : httpStatusCode;
                httpStatusCode = authorizeException.ErrorCode == AuthorizeErrors.RequestTimeout ? (int)HttpStatusCode.RequestTimeout : httpStatusCode;
            }

            context.Response.ContentType = "application/json";
            context.Response.StatusCode = httpStatusCode;
            var result = JsonConvert.SerializeObject(
                new CryptoResponseDto
                {
                    Date = DateTime.Now,
                    Success = false,
                    ErrorCode = ErrorCodeCrypto.ToString(),
                    ErrorDescription = exception.Message
                });

            return context.Response.WriteAsync(result);
        }
    }

    public static class ExceptionHandlerMiddlewareExtensions
    {
        public static void UseExceptionHandlerMiddleware(this IApplicationBuilder app)
        {
            app.UseMiddleware<ExceptionHandlerMiddleware>();
        }
    }

    public static class ExceptionExtensions
    {
        public static Exception GetOriginalException(this Exception ex)
        {
            if (ex.InnerException == null)
                return ex;

            return ex.InnerException.GetOriginalException();
        }
    }
}