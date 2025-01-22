using Albireo.Base32;
using Astra.Hosting.Application;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Astra.Hosting.IdentityServer.MFA.Providers;

public interface IGoogleAuthenticationProvider
{
    Task<string> GenerateSecretKey();
    Task<string> GenerateProvisionUrlAsync(byte[] key, string identifier);
    Task<string> GeneratePinAsync(byte[] key, TimeSpan timeDrift);
}

public sealed class GoogleMfaProvider : IGoogleAuthenticationProvider, IMfaProvider
{
    private const int INTERVAL_LENGTH = 30;
    private const int PIN_LENGTH = 6;
    private static readonly int _pinModulo = (int)Math.Pow(10, PIN_LENGTH);
    private static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    
    private readonly IHostConfiguration _configuration;
    private readonly string _issuerName;
    private readonly HttpClient _httpClient;
    
    public GoogleMfaProvider(IHostConfiguration configuration)
    {
        _configuration = configuration;
        _issuerName = configuration.GetValue("GoogleAuthentication:IssuerName", "Application");
        _httpClient = new HttpClient();
    }

    private async Task<string> InternalGenerateProvisionUrlAsync(string identifier, byte[] key)
    {
        ArgumentNullException.ThrowIfNull(identifier);
        var keyString = Base32.Encode(key);
        return $"otpauth://totp/{_issuerName}:{identifier}?secret={keyString}&issuer={_issuerName}";
    }
    
    private async Task<string> InternalGeneratePinAsync(byte[] key, long counter)
    {
        const int SIZE_OF_INT32 = 4;
        var counterBytes = BitConverter.GetBytes(counter);

        if (BitConverter.IsLittleEndian)
            Array.Reverse(counterBytes);
        
        using var memoryStream = new MemoryStream(counterBytes);
        var hashedCounterBytes = await HMACSHA1.HashDataAsync(key, memoryStream);
        var hashOffset = hashedCounterBytes[^1] & 0xF;

        var selectedBytes = new byte[SIZE_OF_INT32];
        Buffer.BlockCopy(hashedCounterBytes, hashOffset, selectedBytes, 0, SIZE_OF_INT32);

        if (BitConverter.IsLittleEndian)
            Array.Reverse(selectedBytes);

        var selectedInteger = BitConverter.ToInt32(selectedBytes, 0);
        var truncatedHash = selectedInteger & 0x7FFFFFFF;
        var pinString = truncatedHash % _pinModulo;

        return pinString.ToString(CultureInfo.InvariantCulture).PadLeft(PIN_LENGTH, '0');
    }
    
    private long InternalGetCurrentInterval(TimeSpan userTimeDrift)
    {
        if (userTimeDrift.TotalHours is > 24 or < -24)
            throw new ArgumentOutOfRangeException(nameof(userTimeDrift), "Time drift must be within ±24 hours");
        
        var adjustedTime = DateTime.UtcNow.Add(userTimeDrift);
        return (long)Math.Floor((adjustedTime - _unixEpoch).TotalSeconds / INTERVAL_LENGTH);
    }

    public async Task<string> GenerateSecretKey()
    {
        var keyBytes = new byte[20];
        RandomNumberGenerator.Fill(keyBytes);
        return Base32.Encode(keyBytes);
    }
    
    public async Task<string> GenerateProvisionUrlAsync(byte[] key, string identifier) 
        => await InternalGenerateProvisionUrlAsync(identifier, key);
    public async Task<string> GeneratePinAsync(byte[] key, TimeSpan timeDrift) 
        => await InternalGeneratePinAsync(key, InternalGetCurrentInterval(timeDrift));
    
    public MfaType Mfa => MfaType.GoogleAuthenticator;
}