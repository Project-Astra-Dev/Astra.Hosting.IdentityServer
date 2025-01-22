using System.ComponentModel.DataAnnotations;
using System.Security.Cryptography;

namespace Astra.Hosting.IdentityServer.Models;

public interface IUserIdentity
{
    int UserId { get; }
    string Uuid { get; }
    string Username { get; }
    string Email { get; }
    bool PasswordResetRequired { get; }
    string SecurityStamp { get; }
    string[] Roles { get; }
    byte[] Fingerprint { get; }
    byte[] PrivateKey { get; }
    byte[] PublicKey { get; }
    List<TrustedDevice> TrustedDevices { get; set; }
}

public sealed class UserIdentityModel : IUserIdentity
{
    public static (byte[] fingerprint, byte[] priv, byte[] pub) CreateKeyPair()
    {
        using var rsa = new RSACryptoServiceProvider(2048);
        byte[] fingerprint = new byte[40];
        
        RandomNumberGenerator.Fill(fingerprint);
        {
            fingerprint[0] = 0xFF;  fingerprint[1] = 0xF0;
            fingerprint[10] = 0xFF; fingerprint[11] = 0x00;
            fingerprint[20] = 0xFF; fingerprint[21] = 0x00;
            fingerprint[30] = 0xFF; fingerprint[31] = 0x00;
        }
        return (fingerprint, rsa.ExportCspBlob(true), rsa.ExportCspBlob(false));
    }
    
    [Key] public int UserId { get; set; } = 0;
    public string Uuid { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public bool PasswordResetRequired { get; set; } = true;
    public string SecurityStamp { get; set; } = string.Empty;
    public string[] Roles { get; set; } = Array.Empty<string>();
    public byte[] Fingerprint { get; set; } = Array.Empty<byte>();
    public byte[] PrivateKey { get; set; } = Array.Empty<byte>();
    public byte[] PublicKey { get; set; } = Array.Empty<byte>();
    
    
    public List<TrustedDevice> TrustedDevices { get; set; } = new();
    public List<ActiveSession> ActiveSessions { get; set; } = new();
}