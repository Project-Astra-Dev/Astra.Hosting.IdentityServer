using Astra.Hosting.Application;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Astra.Hosting.IdentityServer.MFA.Google;

public interface IGoogleAuthenticationProvider
{
    Task<byte[]> GenerateProvisionAsync(string identifier, int width, int height);
    Task<string> GeneratePinAsync();
}

public sealed class GoogleMfaProvider : IGoogleAuthenticationProvider, IMfaProvider
{
    private const int INTERVAL_LENGTH = 30;
    private const int PIN_LENGTH = 6;
    private static readonly int _pinModulo = (int)Math.Pow(10, PIN_LENGTH);
    private static readonly DateTime _unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
    
    private readonly IHostConfiguration _configuration;
    private readonly byte[] _secretKey;
    private readonly HttpClient _httpClient;
    
    public GoogleMfaProvider(IHostConfiguration configuration)
    {
        _configuration = configuration;
        _secretKey = Convert.FromBase64String(
            _configuration.GetValue<string>("GoogleAuthentication:SecretKey")
        );
        
        _httpClient = new HttpClient();
    }

    private async Task<byte[]> InternalGenerateProvisionAsync(string identifier, byte[] key, int width, int height)
    {
        var keyString = Encoder.Base32Encode(key);
        var provisionUrl = Encoder.UrlEncode($"otpauth://totp/{identifier}?secret={keyString}");
        var chartUrl = $"https://chart.apis.google.com/chart?cht=qr&chs={width}x{height}&chl={provisionUrl}";
        return await _httpClient.GetByteArrayAsync(chartUrl);
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
    
    public async Task<byte[]> GenerateProvisionAsync(string identifier, int width, int height) 
        => await InternalGenerateProvisionAsync(identifier, _secretKey, width, height);
    public async Task<string> GeneratePinAsync() => await InternalGeneratePinAsync(_secretKey, CurrentInterval);
    
    public MfaType Mfa => MfaType.GoogleAuthenticator;
    public long CurrentInterval => (long)Math.Floor((DateTime.UtcNow - _unixEpoch).TotalSeconds) / INTERVAL_LENGTH;
    
    static class Encoder
    {
        internal static string UrlEncode(string value)
        {
            const string URL_ENCODE_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";

            var builder = new StringBuilder();
            for (var i = 0; i < value.Length; i++)
            {
                var symbol = value[i];
                if (URL_ENCODE_ALPHABET.IndexOf(symbol) != -1)
                    builder.Append(symbol);
                else
                {
                    builder.Append('%');
                    builder.Append(((int)symbol).ToString("X2"));
                }
            }

            return builder.ToString();
        }

        internal static string Base32Encode(byte[] data)
        {
            const int IN_BYTE_SIZE = 8;
            const int OUT_BYTE_SIZE = 5;
            const string BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            int i = 0, index = 0;
            var builder = new StringBuilder((data.Length + 7) * IN_BYTE_SIZE/ OUT_BYTE_SIZE);
            while (i < data.Length)
            {
                int currentByte = data[i];
                int digit;
                
                if (index > (IN_BYTE_SIZE - OUT_BYTE_SIZE))
                {
                    int nextByte;
                    if ((i + 1) < data.Length)
                        nextByte = data[i + 1];
                    else nextByte = 0;

                    digit = currentByte & (0xFF >> index);
                    index = (index + OUT_BYTE_SIZE) % IN_BYTE_SIZE;
                    digit <<= index;
                    digit |= nextByte >> (IN_BYTE_SIZE - index);
                    i++;
                }
                else
                {
                    digit = (currentByte >> (IN_BYTE_SIZE - (index + OUT_BYTE_SIZE))) & 0x1F;
                    index = (index + OUT_BYTE_SIZE) % IN_BYTE_SIZE;
                    if (index == 0) i++;
                }

                builder.Append(BASE32_ALPHABET[digit]);
            }

            return builder.ToString();
        }
    }
}