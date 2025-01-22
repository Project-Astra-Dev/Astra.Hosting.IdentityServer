using Astra.Hosting.Autofac;
using Astra.Hosting.EntityFramework;
using Astra.Hosting.IdentityServer.Contexts;
using Astra.Hosting.IdentityServer.Services;
using Autofac;
using System.Runtime.InteropServices;

namespace Astra.Hosting.IdentityServer;

public static class ContainerExtensions
{
    public static ContainerBuilder AddIdentityServer(
        this ContainerBuilder builder, 
        [Optional] Action<IAuthorizationServiceBuilder>? authOptionsAction, 
        [Optional] Action<IdentityServerDatabaseContext>? dbOptionsAction)
    {
        return builder
            .AddDbContext<IIdentityServerDatabaseContext, IdentityServerDatabaseContext>(options =>                         // Create DB Context
                dbOptionsAction?.Invoke((IdentityServerDatabaseContext)options))
            .AddSingleton<IAuthorizationServiceBuilder, AuthorizationServiceBuilder>(options                    // Create Auth Builder
                => authOptionsAction?.Invoke(options))
            .AddSingletonFactory<IAuthorizationService, AuthorizationService>((ctx, parameters)     // Create Singleton Factory
                => AuthorizationServiceBuilder.Instance?.Build() 
                    ?? throw new InvalidOperationException("Authorization service not initialized."));
    }

    public static IContainer UseIdentityServer(this IContainer container)
    {
        
        { // Prewarm IS services
            container.Resolve<IIdentityServerDatabaseContext>();
            container.Resolve<IAuthorizationServiceBuilder>();
            container.Resolve<IAuthorizationService>();
        }
        return container;
    }
}