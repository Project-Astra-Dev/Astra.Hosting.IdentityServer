# Astra.Hosting MFA
To use this package, please use `ContainerExtensions.AddSingleton<,>` with the required
interface and implementation class.

```cs
// For Google Authenticator
interface IGoogleAuthenticationProvider {}
class GoogleMfaProvider : IGoogleAuthenticationProvider { }

// For Generic TOTP Authentication
interface ITotpAuthenticationProvider {}
class TotpMfaProvider : ITotpAuthenticationProvider { }
```
