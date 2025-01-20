using Astra.Hosting.Http.Interfaces;
using Astra.Hosting.IdentityServer.Contexts;
using Astra.Hosting.IdentityServer.Models;

namespace Astra.Hosting.IdentityServer.Processors;

public interface IGrantTypeResponderRegistry
{
    void Register<TProcessor>() where TProcessor : IGrantTypeRequestResponder;
    void Register(IGrantTypeRequestResponder requestResponder);
    bool Contains(string grantType);
    Task<LoginResponse> Process(string grantType, IIdentityServerDatabaseContext identityServerDatabaseContext, IHttpContext context);
}

public sealed class GrantTypeResponderRegistry : IGrantTypeResponderRegistry
{
    private readonly IAuthorizationService _authorizationService;
    private readonly List<IGrantTypeRequestResponder> _requestResponders = new();

    public GrantTypeResponderRegistry(AuthorizationService authorizationService)
    {
        _authorizationService = authorizationService;
    }
    
    public void Register<TProcessor>() where TProcessor : IGrantTypeRequestResponder
        => Register(Activator.CreateInstance<TProcessor>());
    public void Register(IGrantTypeRequestResponder requestResponder) => _requestResponders.Add(requestResponder);
    public bool Contains(string grantType) => _requestResponders.Any(x => x.GrantType == grantType);
    public async Task<LoginResponse> Process(string grantType,  IIdentityServerDatabaseContext identityServerDatabaseContext, IHttpContext context) 
        => await _requestResponders.FirstOrDefault(x =>
        {
            ArgumentNullException.ThrowIfNull(x);
            return x.GrantType == grantType;
        })!.Process(_authorizationService, identityServerDatabaseContext, context);
}