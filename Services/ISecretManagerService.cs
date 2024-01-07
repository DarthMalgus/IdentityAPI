using IdentityAPI.Models;

namespace IdentityAPI.Services
{
    public interface ISecretManagerService
    {
        public Task GetSecretAsync(string secretName);
    }
}
