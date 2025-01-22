namespace Astra.Hosting.IdentityServer.MFA.Providers;

public interface ITotpAuthenticationProvider
{
    
}

// Implementation is going to be worked on soon
public sealed class TotpMfaProvider : ITotpAuthenticationProvider, IMfaProvider
{
    public MfaType Mfa => MfaType.TOTP;
}