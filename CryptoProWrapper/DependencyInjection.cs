using CryptoAPI.Services;
using CryptoProWrapper.GetCertificate;
using CryptoProWrapper.GetSign;
using CryptoProWrapper.GetSignature;
using CryptoProWrapper.GetTspToken;
using CryptoProWrapper.SignatureVerification;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace CryptoProWrapper
{
    public static class DependencyInjection
    {
        public static IServiceCollection ImplementCryptoProCsp(this IServiceCollection services, IConfiguration configuration)
        {
            services.AddScoped<IGetCertificate, AdvapiCertificate>();
            services.AddScoped<IGetCadesSignature, LowLevelCadesDllSignature>();
            services.AddScoped<IEncryptionMessageService, SimplifiedEncryptMessage>();
            services.AddScoped<IGetXadesSignature, SimplifiedXadesDllSignature>();
            services.AddScoped<IValidateCadesSignature, LowlevelCadesVerification>();
            services.AddScoped<IValidateXadesSignature, XadesSignatureVerification>();
            services.AddScoped<IGetTspToken, CryptoProTspClient>();
            services.AddScoped<ISignaturePreparations, SignaturePreparations>();
            return services;
        }

        //public static IServiceCollection ImplementTspClient(this IServiceCollection services, IConfiguration configuration)
        //{
        //    services.AddTransient<IHTTPDataLoader, NetHttpDataLoader>();
        //    services.AddTransient<IHTTPDataLoader, NetHttpDataLoader>();
        //    return services;
        //}
    }
}
