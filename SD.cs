using System.Security.Cryptography;
using System.Text;

namespace IdentityAPI
{
    public static class SD
    {
        public static string ClientSecret { get; set; }
        public static string ClientId { get; set; }
        public static string UserPoolId { get; set; }

        public static string GetSecretHash(string secretKey, string clientId, string username)
        {
            byte[] sercetkeySha = Encoding.UTF8.GetBytes(secretKey);
            byte[] data;
            using (HMACSHA256 hmac = new HMACSHA256(sercetkeySha))
            {
                data = hmac.ComputeHash(Encoding.UTF8.GetBytes(username + clientId));
            }
            return Convert.ToBase64String(data);
        }
    }
}
