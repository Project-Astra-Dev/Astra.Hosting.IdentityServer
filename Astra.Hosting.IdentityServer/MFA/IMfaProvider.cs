namespace Astra.Hosting.IdentityServer.MFA;

public interface IMfaProvider
{
    MfaType Mfa { get; }
}