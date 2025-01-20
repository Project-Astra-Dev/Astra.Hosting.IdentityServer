using Astra.Hosting.Http.Interfaces;
using Astra.Hosting.IdentityServer.Contexts;
using Astra.Hosting.IdentityServer.Models;

namespace Astra.Hosting.IdentityServer.Processors;

public interface IGrantTypeRequestResponder
{
    Task<LoginResponse> Process(IAuthorizationService authorizationService, IIdentityServerDatabaseContext identityServerDatabaseContext, IHttpContext context);
    string GrantType { get; }
}

public abstract class AbstractGrantTypeRequestResponder : IGrantTypeRequestResponder
{
    public abstract Task<LoginResponse> Process(IAuthorizationService authorizationService, IIdentityServerDatabaseContext identityServerDatabaseContext, IHttpContext context);
    public abstract string GrantType { get; }
}