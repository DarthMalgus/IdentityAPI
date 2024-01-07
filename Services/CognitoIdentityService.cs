using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.SecretsManager.Model;
using IdentityAPI.Models;
using System.Text.Json;

namespace IdentityAPI.Services
{
    public class CognitoIdentityService : IIdentityService
    {
        private readonly IAmazonCognitoIdentityProvider _identityProvider;

        public CognitoIdentityService(IAmazonCognitoIdentityProvider identityProvider)
        {
            _identityProvider = identityProvider;
        }

        public async Task<ChangePasswordResponse> ChangePasswordAsync(string oldPassword, string newPassword, string accessToken)
        {
            try
            {
                ChangePasswordRequest request = new ChangePasswordRequest()
                {
                    AccessToken = accessToken,
                    PreviousPassword = oldPassword,
                    ProposedPassword = newPassword
                };
                return await _identityProvider.ChangePasswordAsync(request);
            }
            catch
            {
                throw;
            }
        }

        public async Task<ConfirmSignUpResponse> ConfirmSignUpAsync(string userName, string code)
        {
            try
            {
                ConfirmSignUpRequest request = new ConfirmSignUpRequest()
                {
                    ClientId = SD.ClientId,
                    SecretHash = SD.GetSecretHash(SD.ClientSecret, SD.ClientId, userName),
                    ConfirmationCode = code,
                    Username = userName
                };
                return await _identityProvider.ConfirmSignUpAsync(request);
            }
            catch
            {
                throw;
            }
        }

        public async Task<GetUserResponse> GetUserAsync(string accessToken)
        {
            try 
            { 
                GetUserRequest request = new GetUserRequest() 
                {
                    AccessToken = accessToken
                };
                return await _identityProvider.GetUserAsync(request);
            }
            catch 
            { 
                throw;
            }
        }

        public async Task<AuthFlowResponse> LoginAsync(string loginName, string password)
        {
            try
            {
                CognitoUserPool userPool = new CognitoUserPool(SD.UserPoolId, SD.ClientId, _identityProvider, SD.ClientSecret);
                CognitoUser user = new CognitoUser(loginName, SD.ClientId, userPool, _identityProvider, SD.ClientSecret);

                InitiateSrpAuthRequest authRequest = new InitiateSrpAuthRequest()
                {
                    Password = password,

                };
                return await user.StartWithSrpAuthAsync(authRequest);
            }
            catch
            {
                throw;
            }
        }

        public async Task<GlobalSignOutResponse> LogoutAsync(string accessTocken)
        {
            try
            {
                GlobalSignOutRequest request = new GlobalSignOutRequest()
                {
                    AccessToken = accessTocken,
                };
                return await _identityProvider.GlobalSignOutAsync(request);
            }
            catch 
            {
                throw;
            }
        }

        public async Task<SignUpResponse> SignUpAsync(UserSnapshot user)
        {
            try
            {
                var request = new SignUpRequest()
                {
                    Password = user.Password,
                    Username = user.UserName,
                    ClientId = SD.ClientId
                };
                request.SecretHash = SD.GetSecretHash(SD.ClientSecret, SD.ClientId, user.UserName); ;
                request.UserAttributes.Add(new AttributeType() { Name = "email", Value = user.Email });
                request.UserAttributes.Add(new AttributeType() { Name = "nickname", Value = user.UserName });
                request.UserAttributes.Add(new AttributeType() { Name = "phone_number", Value = user.PhoneNumber });
                request.UserAttributes.Add(new AttributeType() { Name = "name", Value = user.FirstName });
                request.UserAttributes.Add(new AttributeType() { Name = "family_name", Value = user.LastName });
                request.UserAttributes.Add(new AttributeType() { Name = "middle_name", Value = user.MiddleName });

                return await _identityProvider.SignUpAsync(request);
            }
            catch
            {
                throw;
            }
        }
    }
}
