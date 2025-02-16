using CryptoProWrapper;
using CryptoProWrapper.GetSign;
using CryptoProWrapper.GetSignature;
using CryptoProWrapper.SignatureVerification;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CryptoAPI
{
    public class HealthCheckDllLibCapi : IHealthCheck
    {
        const string libcapi20Name = "libcapi20.so";
        public CryptoProvider cryptoProvider { get; set; }

        public HealthCheckDllLibCapi(
            IGetCadesSignature getCadesSignature,
            IGetXadesSignature getXadesSignature,
            IValidateCadesSignature cadesVerify,
            IValidateXadesSignature xadesVerify)
        {
            cryptoProvider = new CryptoProvider(
                getCadesSignature,
                getXadesSignature,
                cadesVerify,
                xadesVerify);
        }

        public Task<HealthCheckResult> CheckDetailHealthAsync()
        {
            string messageResult = $"{libcapi20Name} :";

            try
            {
                var result = cryptoProvider.CheckLibrary(libcapi20Name);

                if (result)
                {
                    return Task.FromResult(HealthCheckResult.Healthy(messageResult + "enable"));
                }
                else
                {
                    messageResult = messageResult + "disabled";
                }
            }
            catch (Exception ex)
            {
                messageResult = messageResult + "disabled" + " - " + ex.Message;
            }

            var healthCheckResult = new HealthCheckResult(status: HealthStatus.Unhealthy, "HealthCheckDllLibCapi " + messageResult);
            return Task.FromResult(healthCheckResult);
        }

        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            return CheckDetailHealthAsync();
        }
    }
}