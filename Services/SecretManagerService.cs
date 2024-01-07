using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using IdentityAPI.Models;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using System.Text.Json;

namespace IdentityAPI.Services
{
    public class SecretManagerService : ISecretManagerService
    {
        private readonly IAmazonSecretsManager _secretManagerService;
        public SecretManagerService(IAmazonSecretsManager secretManager) 
        {
            _secretManagerService = secretManager;
        }

        public async Task GetSecretAsync(string secretName)
        {
            GetSecretValueRequest request = new GetSecretValueRequest
            {
                SecretId = secretName,
                VersionStage = "AWSCURRENT", // VersionStage defaults to AWSCURRENT if unspecified.
            };

            GetSecretValueResponse response;

            try
            {
                response = await _secretManagerService.GetSecretValueAsync(request);
            }
            catch (InvalidRequestException ex)
            {
                throw new InvalidRequestException(ex.Message);
            }

            var clientSecret = JsonSerializer.Deserialize<ClientSecret>(response.SecretString);
            SD.ClientSecret = clientSecret?.ClientSecretValue;
            SD.ClientId = clientSecret?.ClientId;
        }
    }
}
