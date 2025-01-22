using Astra.Hosting.IdentityServer.Contexts;
using Astra.Hosting.IdentityServer.MFA;
using Microsoft.Extensions.DependencyInjection;

namespace Astra.Hosting.IdentityServer.Services;

public interface IAuthorizationServiceBuilder
{
    IAuthorizationServiceBuilder AddClientIdScopes(string clientId, string[] scopes);
    IAuthorizationServiceBuilder AddPossibleAuthorizationMethods(string[] amr);
    IAuthorizationServiceBuilder AddGrantTypeResponder<TProcessor>() where TProcessor : IGrantTypeRequestResponder;
    
    AuthorizationService Build();
}

public sealed class AuthorizationServiceBuilder : IAuthorizationServiceBuilder
{
    public static AuthorizationServiceBuilder? Instance { get; private set; }
    
    private readonly IIdentityServerDatabaseContext _identityServerDatabaseContext;
    private readonly List<AuthorizationScopeDescriptor> _scopes = new();
    private readonly List<string> _allowedAuthorizationMethods = new();
    private readonly List<Type> _grantTypeProviders = new();

    public AuthorizationServiceBuilder(IIdentityServerDatabaseContext identityServerDatabaseContext)
    {
        Instance = this;
        _identityServerDatabaseContext = identityServerDatabaseContext;
    }

    public IAuthorizationServiceBuilder AddClientIdScopes(string clientId, string[] scopes)
    {
        _scopes.Add(new AuthorizationScopeDescriptor { clientId = clientId, scopes = scopes });
        return this;
    }
    
    public IAuthorizationServiceBuilder AddPossibleAuthorizationMethods(string[] amr)
    {
        _allowedAuthorizationMethods.AddRange(amr);
        return this;
    }

    public IAuthorizationServiceBuilder AddGrantTypeResponder<TProcessor>() where TProcessor : IGrantTypeRequestResponder
    {
        _grantTypeProviders.Add(typeof(TProcessor));
        return this;
    }

    public AuthorizationService Build() => new AuthorizationService(
        _identityServerDatabaseContext,
        _scopes, 
        _allowedAuthorizationMethods.ToArray(),
        _grantTypeProviders.ToArray());
}