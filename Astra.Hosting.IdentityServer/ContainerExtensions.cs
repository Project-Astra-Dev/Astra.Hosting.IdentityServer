using Astra.Hosting.Autofac;
using Astra.Hosting.EntityFramework;
using Astra.Hosting.IdentityServer.Contexts;
using Autofac;
using System.Runtime.InteropServices;

namespace Astra.Hosting.IdentityServer;

public static class ContainerExtensions
{
    public static ContainerBuilder AddIdentityServer(
        this ContainerBuilder builder, 
        [Optional] Action<AuthorizationService>? authOptionsAction, 
        [Optional] Action<IdentityServerDatabaseContext>? dbOptionsAction)
    {
        return builder
            .AddDbContext<IIdentityServerDatabaseContext, IdentityServerDatabaseContext>(options =>
                dbOptionsAction?.Invoke((IdentityServerDatabaseContext)options))
            .AddSingleton<IAuthorizationService, AuthorizationService>(options => authOptionsAction?.Invoke(options));
    }

    public static IContainer UseIdentityServer(this IContainer container)
    {
        container.Resolve<IIdentityServerDatabaseContext>();
        container.Resolve<IAuthorizationService>();
        return container;
    }
}