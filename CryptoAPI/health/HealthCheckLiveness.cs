using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CryptoAPI
{
    public class HealthCheckLiveness : IHealthCheck
    {
        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            var HealthCheckResult = new HealthCheckResult();
            HealthCheckResult = new HealthCheckResult(status: HealthStatus.Healthy);
            return Task.FromResult(HealthCheckResult);
        }
    }
}