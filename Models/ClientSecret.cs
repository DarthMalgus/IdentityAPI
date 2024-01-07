using System.Text.Json.Serialization;
using ThirdParty.Json.LitJson;

namespace IdentityAPI.Models
{
    public class ClientSecret
    {
        [JsonPropertyName("client_Id")]
        public string ClientId { get; set; }

        [JsonPropertyName("client_secret")]
        public string ClientSecretValue { get; set; }
    }
}
