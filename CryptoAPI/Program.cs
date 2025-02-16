using CryptoAPI;
using CryptoAPI.Extensions;
using CryptoAPI.Services;
using CryptoProWrapper;
using System.Reflection;
using System.Text.Json.Serialization;
using CryptoAPI.Middlewares;

public partial class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers().AddJsonOptions(options => options.JsonSerializerOptions.Converters.Add(new JsonStringEnumConverter()));

        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromSeconds(1800);
            options.Cookie.HttpOnly = true;
            options.Cookie.IsEssential = true;
        });
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services.AddScoped<IAdminDataService, AdminDataService>();
        builder.Services.AddScoped<ISignatureService, SignatureWinService>();
        builder.Services.AddScoped<IEncryptionService, EncryptionService>();

        builder.Services.AddSession();
        builder.Services.AddHttpClient();

        builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();
        builder.Services.ImplementCryptoProCsp(builder.Configuration);

        // Configure the API versioning properties of the project. 
        builder.Services.AddApiVersioningConfigured();
        // Add a Swagger generator and Automatic Request and Response annotations:
        builder.Services.AddSwaggerSwashbuckleConfigured();

        SettingsHealhCheck.RegestryHealhCheck(builder.Services);

        var app = builder.Build();

        app.UseExceptionHandlerMiddleware();


        Assembly assem = Assembly.GetExecutingAssembly();
        AssemblyName aName = assem.GetName();

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            // Enable middleware to serve the generated OpenAPI definition as JSON files.
            app.UseSwagger();

            // Enable middleware to serve Swagger-UI (HTML, JS, CSS, etc.) by specifying the Swagger JSON files(s).
            var descriptionProvider = app.Services.GetRequiredService<Microsoft.AspNetCore.Mvc.ApiExplorer.IApiVersionDescriptionProvider>();
            app.UseSwaggerUI(options =>
            {
                // Build a swagger endpoint for each discovered API version
                foreach (var description in descriptionProvider.ApiVersionDescriptions)
                {
                    options.SwaggerEndpoint($"{description.GroupName}/swagger.json", description.GroupName.ToUpperInvariant());
                }
            });
        }

        if (aName != null)
        {
            string logMsg = "The app " + aName.Name?.ToString() + "version is " + aName.Version?.ToString();
        }

        app.UseHttpsRedirection();
        app.UseSession();
        app.UseRouting();

        SettingsHealhCheck.EndpointsHealhCheck(app);

        app.UseAuthorization();
        app.MapControllers();
        app.Run();
    }
}

public static class Config
{
    public static bool IsMaintenanceModeEnabled = false;
}