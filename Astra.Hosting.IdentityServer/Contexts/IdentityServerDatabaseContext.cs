using Astra.Hosting.EntityFramework.Contexts;
using Astra.Hosting.IdentityServer;
using Astra.Hosting.IdentityServer.Models;
using Microsoft.EntityFrameworkCore;

namespace Astra.Hosting.IdentityServer.Contexts;

public interface IIdentityServerDatabaseContext : IAstraDatabaseContext
{
    DbSet<UserIdentityModel> Accounts { get; set; }
    DbSet<ActiveSession> ActiveSessions { get; set; }
    DbSet<TrustedDevice> TrustedDevices { get; set; }
}

public sealed class IdentityServerDatabaseContext : AstraDatabaseContextBase, IIdentityServerDatabaseContext, IAstraDatabaseContext
{
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<UserIdentityModel>()
            .Property(e => e.Roles)
            .HasConversion(
                v => string.Join(',', v),
                v => v.Split(',', StringSplitOptions.RemoveEmptyEntries) 
            );
    }

    public DbSet<UserIdentityModel> Accounts { get; set; }
    public DbSet<ActiveSession> ActiveSessions { get; set; }
    public DbSet<TrustedDevice> TrustedDevices { get; set; }
    
    public override string DatabaseName => "IdentityServer";
}