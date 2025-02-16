using Microsoft.AspNetCore.Diagnostics.HealthChecks;

namespace CryptoAPI
{
    public static class SettingsHealhCheck
    {
        public static void RegestryHealhCheck(IServiceCollection Services)
        {
            Services.AddTransient<HealthCheckDllLibCapi>();
            Services.AddTransient<HealthCheckDllCades>();
            Services.AddTransient<HealthCheckTSPServices>();

            Services.AddHealthChecks()
         .AddCheck<HealthCheckLiveness>(name: "Health_Liveness", tags: new List<string>() { "Liveness" });
                 
            Services.AddHealthChecks()
                .AddCheck<HealthCheckDllCades>(name: "Сades", tags: new List<string>() { "Readiness" });

            Services.AddHealthChecks()
                .AddCheck<HealthCheckTSPServices>(name: "TSP_health_check", tags: new List<string>() { "Readiness" });
        }
        ///регистрациия ендпойнтов хелфчека 
        public static void EndpointsHealhCheck(WebApplication app)
        {
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapHealthChecks("/health/live", new HealthCheckOptions
                {
                    Predicate = check => check.Tags.Contains("Liveness")
                });

                endpoints.MapHealthChecks("/health/ready", new HealthCheckOptions
                {
                    Predicate = check => check.Tags.Contains("Readiness")
                });

                endpoints.MapControllers();
            });

            app.UseEndpoints(endpoints =>
            {
                // Отдельный кастомный IHealthCheck
                endpoints.Map("/health/Liveness/details", async context =>
                {
                    var stringResult = string.Empty;

                    var myHealthCheck = context.RequestServices.GetService<HealthCheckDllCades>();
                    if (myHealthCheck != null)
                    {
                        var result = await myHealthCheck.CheckDetailHealthAsync();
                        stringResult = stringResult + $"Status: {result.Status}, Duration: {result.Description};" + Environment.NewLine;
                    }

                    var myHealthCheckDllLibCapi = context.RequestServices.GetService<HealthCheckDllLibCapi>();
                    if (myHealthCheckDllLibCapi != null)
                    {
                        var resultLibCapi = await myHealthCheckDllLibCapi.CheckDetailHealthAsync();
                        stringResult = stringResult + $"Status: {resultLibCapi.Status}, Duration: {resultLibCapi.Description};" + Environment.NewLine;
                    }

                    await context.Response.WriteAsync(stringResult);
                });
            });

        }
    }
}
