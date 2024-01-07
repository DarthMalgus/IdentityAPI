using Amazon;
using Amazon.CognitoIdentityProvider;
using Amazon.CognitoIdentityProvider.Model;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime.Internal;
using Amazon.Runtime.Internal.Transform;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using IdentityAPI.Models;
using IdentityAPI.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace IdentityAPI.Controllers
{
    [Route("Identity")]
    [ApiController]
    public class IdentityController : ControllerBase
    {
        private readonly IIdentityService _identityService;
        public IdentityController(IIdentityService identityService)
        {
            _identityService = identityService;
        }

        [HttpPost]
        [Route("/signup")]
        public async Task<IActionResult> SignUpAsync([FromBody] UserSnapshot user)
        {
            try
            {
                var signUpResponse = await _identityService.SignUpAsync(user);
                return Ok(signUpResponse);
            }
            catch (JsonException jex)
            {
                return StatusCode(500, jex.Message);
            }
            catch (ForbiddenException fe)
            {
                return Forbid(fe.Message);
            }
            catch (InternalErrorException ie)
            {
                return StatusCode(500, ie.Message);
            }
            catch (InvalidPasswordException ipase)
            {
                return BadRequest(ipase.Message);
            }
            catch (InvalidRequestException ire)
            {
                return BadRequest(ire.Message);
            }
            catch (Exception e)
            {
                return StatusCode(500, e.Message);
            }

        }

        [HttpPost]
        [Route("/login")]
        public async Task<IActionResult> LoginAsync([FromBody] Login login)
        {
            try
            {
                var response = await _identityService.LoginAsync(login.LoginName, login.Password);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        [HttpPost]
        [Route("/changepassword")]
        [Authorize]
        public async Task<IActionResult> ChangePasswordAsync([FromBody] ChgPassword chgPassword)
        {
            try
            {
                string? accessToken = await HttpContext.GetTokenAsync("access_token");
                var response = await _identityService.ChangePasswordAsync(chgPassword.OldPassword, chgPassword.NewPassword, accessToken);
                return Ok(response);
            }
            catch (ForbiddenException fe)
            {
                return Forbid(fe.Message);
            }
            catch (InvalidPasswordException ipase)
            {
                return BadRequest(ipase.Message);
            }
            catch (NotAuthorizedException nae)
            {
                return StatusCode(401, nae.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        [Authorize]
        [HttpGet]
        [Route("/logout")]
        public async Task<IActionResult> LogoutAsync()
        {
            try 
            {
                string? accessTocken = await HttpContext.GetTokenAsync("access_token");
                var response = await _identityService.LogoutAsync(accessTocken);
                return Ok(response);
            }
            catch (ForbiddenException fe) 
            {
                return Forbid(fe.Message);
            }
            catch (Exception ex) 
            {
                return StatusCode(500, ex.Message);
            }
        }

        [HttpGet]
        [Route("/signup/confirm/{userName}/{code}")]
        public async Task<IActionResult> ConfirmSignUpAsync(string userName, string code)
        {
            try
            {
                var response = await _identityService.ConfirmSignUpAsync(userName, code);
                return Ok(response);
            }
            catch (ForbiddenException fe)
            {
                return Forbid(fe.Message);
            }
            catch (CodeMismatchException cme)
            {
                return BadRequest(cme.Message);
            }
            catch (ExpiredCodeException ece)
            {
                return BadRequest(ece.Message);
            }
            catch (UserNotFoundException unfe)
            {
                return NotFound(unfe.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }

        [HttpGet]
        [Authorize]
        [Route("/user")]
        public async Task<IActionResult> GetUserAsync()
        {
            try 
            { 
                string? accessTocken = await HttpContext.GetTokenAsync("access_token");
                var response = await _identityService.GetUserAsync(accessTocken);
                return Ok(response);
            }
            catch (ForbiddenException fe) 
            {
                return Forbid(fe.Message);
            }
            catch (UserNotFoundException unfe)
            {
                return NotFound(unfe.Message);
            }
            catch (NotAuthorizedException nae)
            {
                return StatusCode(401, nae.Message);
            }
            catch (Exception ex)
            {
                return StatusCode(500, ex.Message);
            }
        }
    }
}
