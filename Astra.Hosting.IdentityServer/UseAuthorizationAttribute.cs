using System.Net;
using System.Runtime.InteropServices;
using Astra.Hosting.Application;
using Astra.Hosting.Http.Attributes;
using Astra.Hosting.Http.Interfaces;
using Astra.Hosting.IdentityServer.Services;
using Microsoft.Net.Http.Headers;

namespace Astra.Hosting.IdentityServer;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = false)]
public sealed class UseAuthorizationAttribute : HttpProcessorAttribute
{
    public UseAuthorizationAttribute([Optional] string[]? roles, [Optional] string[]? scopes)
    {
        Roles = roles ?? [];
        Scopes = scopes ?? [];
    }
    
    public override async Task<bool> Validate(IHttpContext httpContext)
    {
        if (httpContext.Request.Headers.ContainsKey(HeaderNames.Authorization))
        {
            var authorizationService = HostApplication.Instance.Get<IAuthorizationService>();
            httpContext.Session = await authorizationService.GetSessionAsync(httpContext.Request);
            return (Scopes.Length == 0 || Scopes.All(x => httpContext.Session.Scopes.Contains(x))) &&
                   (Roles.Length == 0 || Roles.All(x => httpContext.Session.Roles.Contains(x)));
        }
        return false;
    }
    
    public string[] Roles { get; set; }
    public string[] Scopes { get; set; }
}