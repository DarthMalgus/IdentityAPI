using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using IdentityAPI.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAPI.Services
{
    public interface IIdentityService
    {
        public Task<SignUpResponse> SignUpAsync(UserSnapshot user);
        public Task<GlobalSignOutResponse> LogoutAsync(string accessTocken);
        public Task<AuthFlowResponse> LoginAsync(string loginName, string password);
        public Task<ChangePasswordResponse> ChangePasswordAsync(string oldPassword, string newPassword, string accessTocken);
        public Task<ConfirmSignUpResponse> ConfirmSignUpAsync(string userName, string code);
        public Task<GetUserResponse> GetUserAsync(string accessToken);
    }
}
