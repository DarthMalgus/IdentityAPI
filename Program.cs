using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.Extensions.NETCore.Setup;
using Amazon.Runtime;
using Amazon.SecretsManager;
using IdentityAPI.Services;
using Microsoft.OpenApi.Models;
using System.Net;
using System.Text.Json;
using Newtonsoft.Json;
using Microsoft.IdentityModel.Tokens;

namespace IdentityAPI
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            //builder.Services.

           

            SD.ClientId = builder.Configuration["ClientID"];
            SD.UserPoolId = builder.Configuration["UserPoolID"];
            SD.ClientSecret = builder.Configuration["ClientSecret"];

            AWSOptions options = new AWSOptions()
            {
                Region = RegionEndpoint.EUNorth1,
                Credentials = new BasicAWSCredentials(SD.ClientId, SD.ClientSecret)
            };

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(c => {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "Mango.Services.ProductAPI", Version = "1.0" });
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = @"Enter 'Bearer' [space] and your token",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });
                c.AddSecurityRequirement(new OpenApiSecurityRequirement {
                    {
                        new OpenApiSecurityScheme
                        {
                            Reference = new OpenApiReference
                            {
                                Type = ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            },
                            Scheme = "oauth2",
                            Name = "Bearer",
                            In = ParameterLocation.Header
                        },
                        new List<string>()
                    }
                });
            });
            builder.Services.AddAWSService<IAmazonCognitoIdentityProvider>(options);
            builder.Services.AddSingleton<IIdentityService, CognitoIdentityService>();
            builder.Services.AddAWSLambdaHosting(LambdaEventSource.HttpApi);
            builder.Services.AddAuthentication("Bearer")
                .AddJwtBearer(options =>
                {
                    options.SaveToken = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKeyResolver = (s, securityToken, identifier, parameters) =>
                        {
                            // Get JsonWebKeySet from AWS
                            var json = new WebClient().DownloadString(parameters.ValidIssuer + "/.well-known/jwks.json");
                            var keySet = JsonConvert.DeserializeObject<JsonWebKeySet>(json);
                            var keys = keySet.Keys;
                            // Serialize the result
                            return (IEnumerable<SecurityKey>)keys;
                        },
                        ValidateIssuer = true,
                        ValidIssuer = $"https://cognito-idp.{RegionEndpoint.EUNorth1.SystemName}.amazonaws.com/{SD.UserPoolId}",
                        ValidateLifetime = true,
                        LifetimeValidator = (before, expires, token, param) => expires > DateTime.UtcNow,
                        ValidateAudience = false,
                        ValidAudience = SD.ClientId,
                        RequireAudience = false
                    };
                });


            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            //app.MapPost()

            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}