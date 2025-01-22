namespace Astra.Hosting.IdentityServer.MFA.TOTP;

public sealed class TotpMfaProvider : IMfaProvider
{
    public MfaType Mfa => MfaType.TOTP;
}