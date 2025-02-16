using CryptoProWrapper;
using CryptoProWrapper.GetSign;
using CryptoProWrapper.GetSignature;
using CryptoProWrapper.SignatureVerification;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CryptoAPI
{
    public class HealthCheckDllCades : IHealthCheck
    {
        const string libxadesName = "libxades.so";
        public CryptoProvider cryptoProvider { get; set; }

        public HealthCheckDllCades(
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
            string messageResult = $"{libxadesName} :";

            try
            {
                var result = cryptoProvider.CheckLibrary(libxadesName);

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

            var healthCheckResult = new HealthCheckResult(status: HealthStatus.Unhealthy, "HealthCheckDllСades " + messageResult);
            return Task.FromResult(healthCheckResult);
        }

        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            return CheckDetailHealthAsync();
        }
    }
}