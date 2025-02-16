using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace CryptoAPI
{
    public class HealthCheckTSPServices : IHealthCheck
    {
        string message = "TSP: ";
        private readonly IConfiguration Configuration;
        private readonly string _BaseUrl;

        public HealthCheckTSPServices(IConfiguration configuration)
        {
            Configuration = configuration;
            string? baseUr = "адрес TSP сервера";

            if (!string.IsNullOrEmpty(baseUr))
            {
                _BaseUrl = baseUr;
            }
        }

        public Task<HealthCheckResult> CheckDetailHealthAsync()
        {
            try
            {
                var client = new HttpClient();
                var request = new HttpRequestMessage(HttpMethod.Get,_BaseUrl);
                request.Headers.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7");
                request.Headers.Add("Accept-Language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7");
                request.Headers.Add("Connection", "keep-alive");
                request.Headers.Add("Upgrade-Insecure-Requests", "1");
                request.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36");
                var response =  client.SendAsync(request).Result;
                response.EnsureSuccessStatusCode();
               
                if (response.Content.ReadAsStringAsync().Result.Length > 1)
                {
                    return Task.FromResult(HealthCheckResult.Healthy($"{message} enable, URL: {_BaseUrl}"));
                }
                else
                {
                    return Task.FromResult(HealthCheckResult.Unhealthy($"{message} disable, URL: {_BaseUrl}"));
                }
            }
            catch (Exception ex)
            {
                message = message + "disabled" + " - " + ex.Message + "url:" + _BaseUrl;
            }

            var healthCheckResult = new HealthCheckResult(status: HealthStatus.Unhealthy, "HealthCheckTSP " + message + "url:" + _BaseUrl);

            return Task.FromResult(healthCheckResult);
        }

        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            return CheckDetailHealthAsync();
        }
    }
}
 