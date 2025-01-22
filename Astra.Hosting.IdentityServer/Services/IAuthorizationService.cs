using Astra.Hosting.Http.Interfaces;
using Astra.Hosting.IdentityServer.Models;
using System.Runtime.InteropServices;

namespace Astra.Hosting.IdentityServer.Services;

public interface IAuthorizationService
{
    IAuthorizationService SetClientIdScopes(string clientId, string[] scopes);
    IAuthorizationService SetAuthorizationMethods(string[] amr);
    
    Task<IHttpSession> GetSessionAsync(IHttpRequest request);
    Task<bool> IsAuthenticatedAsync(IUserIdentity userIdentity, string sessionId);
    Task<IUserIdentity> CreateUserIdentityAsync(string username, [Optional] string emailAddress, [Optional] string password);
    Task<LoginResponse> AttemptLoginAsync(string usernameOrEmail, string password, string grantType, string clientId);
    Task<LoginResponse> AttemptLoginAsync(IUserIdentity userIdentity, string grantType, string clientId);
    Task<bool> AttemptLogoutAsync(IUserIdentity userIdentity);
    Task<bool> AttemptLogoutAsync(IUserIdentity userIdentity, string sessionId);
    Task<bool> ValidatePasswordAsync(IUserIdentity userIdentity, string passwordUnhashed);
    Task<bool> ResetPasswordAsync(IUserIdentity userIdentity, bool requirePasswordReset);
    Task<bool> AddTrustedDeviceAsync(IUserIdentity userIdentity, string name, string deviceId);
    Task<bool> RemoveTrustedDeviceAsync(IUserIdentity userIdentity, string trustId);
    Task<bool> HasTrustedDeviceAsync(IUserIdentity userIdentity, string deviceId);
    
    IGrantTypeResponderRegistry GrantTypeRegistry { get; }
}