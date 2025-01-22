using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Astra.Hosting;
using Astra.Hosting.Http;
using Astra.Hosting.Http.Interfaces;
using Astra.Hosting.IdentityServer.Contexts;
using Astra.Hosting.IdentityServer.Models;
using Astra.Hosting.IdentityServer.Processors;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Runtime.InteropServices;

namespace Astra.Hosting.IdentityServer;

public class AuthorizationScopeDescriptor
{
    public string clientId;
    public string[] scopes;
}

public interface IAuthorizationService
{
    IAuthorizationService SetClientIdScopes(string clientId, string[] scopes);
    IAuthorizationService SetAuthorizationMethods(string[] amr);
    
    
    Task<IHttpSession> GetSessionAsync(IHttpRequest request);
    Task<bool> IsAuthenticatedAsync(IUserIdentity userIdentity, string sessionId);
    Task<IUserIdentity> CreateUserIdentityAsync(string username, [Optional] string emailAddress, [Optional] string password);
    Task<LoginResponse> AttemptLoginAsync(string usernameOrEmail, string password, string grantType, string clientId);
    Task<LoginResponse> AttemptLoginAsync(IUserIdentity userIdentity, string grantType, string clientId);
    Task<bool> AttemptLogoutAsync(IUserIdentity userIdentity, string sessionId);
    Task<bool> ValidatePasswordAsync(IUserIdentity userIdentity, string passwordUnhashed);
    Task<bool> ResetPasswordAsync(IUserIdentity userIdentity, bool requirePasswordReset);
    Task<bool> AddTrustedDeviceAsync(IUserIdentity userIdentity, string name, string deviceId);
    Task<bool> RemoveTrustedDeviceAsync(IUserIdentity userIdentity, string trustId);
    Task<bool> HasTrustedDeviceAsync(IUserIdentity userIdentity, string deviceId);
    
    IGrantTypeResponderRegistry GrantTypeRegistry { get; }
}

public sealed class AuthorizationService : IAuthorizationService
{
    private static readonly ILogger _logger = ModuleInitialization.InitializeLogger(nameof(AuthorizationService));

    private readonly IIdentityServerDatabaseContext _identityDatabaseContext;
    private readonly IGrantTypeResponderRegistry _responderRegistry;

    private static List<AuthorizationScopeDescriptor> _authorizationScopes = new();
    private static string[] _allowedAuthenticationMethods = Array.Empty<string>();

    public AuthorizationService(IIdentityServerDatabaseContext identityDatabaseContext)
    {
        _identityDatabaseContext = identityDatabaseContext;
        _responderRegistry = new GrantTypeResponderRegistry(this);
    }

    [Flags]
    public enum PasswordCharacterSets
    {
        None = 0,
        Letters = 1 << 0, // Includes both upper and lowercase
        Numbers = 1 << 1,
        Symbols = 1 << 2,
        All = Letters | Numbers | Symbols
    }

    public static class PasswordManager
    {
        private const int KEY_SIZE = 64;
        private const int ITERATIONS = 5000;

        private static readonly char[] _lowercaseLetters = "abcdefghijklmnopqrstuvwxyz".ToCharArray();
        private static readonly char[] _uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".ToCharArray();
        private static readonly char[] _numbers = "0123456789".ToCharArray();
        private static readonly char[] _symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?".ToCharArray();

        public static string GeneratePassword(int length, PasswordCharacterSets options)
        {
            if (length < 8)
                throw new ArgumentException("Password length must be at least 8 characters", nameof(length));
            if (options == PasswordCharacterSets.None)
                throw new ArgumentException("At least one character set must be selected", nameof(options));

            var password = new char[length];
            var availablePositions = Enumerable.Range(0, length).ToList();

            if (options.HasFlag(PasswordCharacterSets.Letters))
            {
                InsertRandomCharacter(password, availablePositions, _lowercaseLetters);
                InsertRandomCharacter(password, availablePositions, _uppercaseLetters);
            }
            if (options.HasFlag(PasswordCharacterSets.Numbers))
                InsertRandomCharacter(password, availablePositions, _numbers);
            if (options.HasFlag(PasswordCharacterSets.Symbols))
                InsertRandomCharacter(password, availablePositions, _symbols);

            var allAllowedChars = new List<char>();
            if (options.HasFlag(PasswordCharacterSets.Letters))
            {
                allAllowedChars.AddRange(_lowercaseLetters);
                allAllowedChars.AddRange(_uppercaseLetters);
            }
            if (options.HasFlag(PasswordCharacterSets.Numbers))
                allAllowedChars.AddRange(_numbers);
            if (options.HasFlag(PasswordCharacterSets.Symbols))
                allAllowedChars.AddRange(_symbols);

            while (availablePositions.Count > 0)
                InsertRandomCharacter(password, availablePositions, allAllowedChars.ToArray());
            return new string(password);
        }

        private static void InsertRandomCharacter(char[] password, List<int> availablePositions, char[] characterSet)
        {
            int positionIndex = RandomNumberGenerator.GetInt32(availablePositions.Count);
            int position = availablePositions[positionIndex];
            availablePositions.RemoveAt(positionIndex);

            password[position] = characterSet[RandomNumberGenerator.GetInt32(characterSet.Length)];
        }

        public static string HashPassword(string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be empty", nameof(password));

            byte[] salt = new byte[KEY_SIZE];
            using (var rng = RandomNumberGenerator.Create())
                rng.GetBytes(salt);

            byte[] hash = GenerateHash(password, salt);
            byte[] hashBytes = new byte[salt.Length + hash.Length];
            Buffer.BlockCopy(salt, 0, hashBytes, 0, salt.Length);
            Buffer.BlockCopy(hash, 0, hashBytes, salt.Length, hash.Length);
            return Convert.ToBase64String(hashBytes);
        }

        public static bool ValidatePassword(string password, string hashedPassword)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentException("Password cannot be empty", nameof(password));

            if (string.IsNullOrEmpty(hashedPassword))
                throw new ArgumentException("Hashed password cannot be empty", nameof(hashedPassword));

            try
            {
                byte[] hashBytes = Convert.FromBase64String(hashedPassword);
                byte[] salt = new byte[KEY_SIZE];
                Buffer.BlockCopy(hashBytes, 0, salt, 0, KEY_SIZE);

                byte[] hash = new byte[hashBytes.Length - KEY_SIZE];
                Buffer.BlockCopy(hashBytes, KEY_SIZE, hash, 0, hashBytes.Length - KEY_SIZE);

                byte[] computedHash = GenerateHash(password, salt);
                return CryptographicOperations.FixedTimeEquals(hash, computedHash);
            }
            catch (Exception) { return false; }
        }

        private static byte[] GenerateHash(string password, byte[] salt)
        {
            using var hmac = new HMACSHA512(salt);
            byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
            byte[] hash = passwordBytes;

            for (int i = 0; i < ITERATIONS; i++)
                hash = hmac.ComputeHash(hash);
            return hash;
        }
    }

    // jwt token manager
    public static class TokenManager
    {
        public static readonly TimeSpan GlobalTokenExpiry = TimeSpan.FromHours(10);

        public static byte[] GetSecretKey()
        {
            string filePath = OperatingSystem.IsWindows()
                ? Path.Combine(Environment.CurrentDirectory, "usr/secret")
                : "/usr/secret";

            if (!File.Exists(filePath))
                return Array.Empty<byte>();
            return Encoding.UTF8.GetBytes(File.ReadAllText(filePath));
        }

        public static string[] GetClaimsForClientId(string clientId)
            => _authorizationScopes.FirstOrDefault(x => x.clientId == clientId, defaultValue: null)?.scopes
                ?? Array.Empty<string>();

        public static string GetJwtPassword()
        {
            string filePath = OperatingSystem.IsWindows()
                ? Path.Combine(Environment.CurrentDirectory, "usr/jwt/password")
                : "/usr/jwt/password";

            if (!File.Exists(filePath))
                return string.Empty;
            return File.ReadAllText(filePath);
        }

        public static (bool success, string token, string? error, string? errorDescription) GenerateToken(IUserIdentity userIdentity, string clientId, out string sessionId)
        {
            sessionId = string.Empty;

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = GetSecretKey();
            if (key.Length == 0) return (false, string.Empty, "invalid_request", "(server) /usr/secret does not exist");

            var scopes = GetClaimsForClientId(clientId);
            if (scopes.Length == 0) return (false, string.Empty, "invalid_client", "(server) invalid client_id provided");

            sessionId = Guid.NewGuid().ToString();
            var claimsIdentity = new ClaimsIdentity();

            claimsIdentity.AddClaim(new Claim("client_id", "recroom"));
            claimsIdentity.AddClaim(new Claim("auth_time", DateTime.UtcNow.Ticks.ToString()));
            claimsIdentity.AddClaim(new Claim("idp", "local"));
            claimsIdentity.AddClaim(new Claim("sub", userIdentity.UserId.ToString()));
            claimsIdentity.AddClaim(new Claim("jti", Hashing.SHA1(userIdentity.SecurityStamp + "-" + userIdentity.UserId)));

            claimsIdentity.AddClaim(userIdentity.Roles.Length > 1
                ? new Claim("role", JsonSerializer.Serialize(userIdentity.Roles), JsonClaimValueTypes.JsonArray)
                : new Claim("role", userIdentity.Roles[0]));
            claimsIdentity.AddClaim(new Claim("scope", JsonSerializer.Serialize(scopes), JsonClaimValueTypes.JsonArray));
            claimsIdentity.AddClaim(new Claim("amr", JsonSerializer.Serialize(_allowedAuthenticationMethods), JsonClaimValueTypes.JsonArray));
            claimsIdentity.AddClaim(new Claim("sid", sessionId));

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                IncludeKeyIdInHeader = true,
                Issuer = "auth:astra:gdn:recroom",
                Audience = "recroom:astra",
                Expires = DateTime.UtcNow.Add(GlobalTokenExpiry),
                Subject = claimsIdentity,
                #if DEBUG
                SigningCredentials = new SigningCredentials(
                    new SymmetricSecurityKey(key),
                    SecurityAlgorithms.HmacSha256Signature)
                #elif !DEBUG
                SigningCredentials = new SigningCredentials(
                    new RsaSecurityKey(new X509Certificate2("/usr/jwt/ca_certificate.crt", GetJwtPassword()).GetRSAPrivateKey()
                        ?? throw new InvalidOperationException()),
                    SecurityAlgorithms.RsaSha256Signature)
                #endif
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return (true, tokenHandler.WriteToken(token), null, null);
        }

        public static bool ValidateToken(string token, out JwtSecurityToken? validatedToken)
        {
            validatedToken = null;
            var tokenHandler = new JwtSecurityTokenHandler();

            var key = GetSecretKey();
            if (key.Length == 0) return false;

            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(key),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidIssuer = "auth:astra:gdn:recroom",
                    ValidAudience = "recroom:astra",
                    ClockSkew = TimeSpan.Zero
                }, out var securityToken);
                validatedToken = (JwtSecurityToken)securityToken;

                return true;
            }
            catch { return false; }
        }
    }

    public IAuthorizationService SetClientIdScopes(string clientId, string[] scopes)
    {
        _authorizationScopes.Add(new AuthorizationScopeDescriptor
        {
            clientId = clientId,
            scopes = scopes
        });
        return this;
    }

    public IAuthorizationService SetAuthorizationMethods(string[] amr)
    {
        _allowedAuthenticationMethods = amr;
        return this;
    }

    public async Task<IHttpSession> GetSessionAsync(IHttpRequest request)
    {
        string authorization = string.Empty;
        if (string.IsNullOrEmpty(authorization = request.GetHeaderValue("Authorization") ?? ""))
            return AstraHttpSession.Default;

        if (authorization.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) &&
            TokenManager.ValidateToken(authorization.Substring("Bearer ".Length), out var authorizationToken))
        {
            var claims = authorizationToken!.Claims.Any()
                ? authorizationToken.Claims
                    .GroupBy(x => x.Type)
                    .Select(group => new KeyValuePair<string, string>(
                        group.Key,
                        string.Join(",", group.Select(x => x.Value))))
                    .ToList().ToDictionary()
                : new List<KeyValuePair<string, string>>().ToDictionary();

            var roles = claims.Any(x => x.Key == "role") ? claims["role"].Split(',', StringSplitOptions.RemoveEmptyEntries).ToList() : [];
            var scopes = claims.Any(x => x.Key == "scope") ? claims["scope"].Split(',', StringSplitOptions.RemoveEmptyEntries).ToList() : [];

            var session = AstraHttpSession.New(
                Guid.Empty.ToString(),
                "Bearer",
                authorizationToken!.ValidTo,
                roles,
                scopes,
                claims.ToDictionary()
            );

            if (!int.TryParse(session.Claims["sub"], out var userId))
                return AstraHttpSession.Default;

            var userIdentity = await _identityDatabaseContext.Accounts.FindAsync(userId);
            if (userIdentity == null || !await IsAuthenticatedAsync(userIdentity, session.Claims["sid"]))
                return AstraHttpSession.Default;
            return session;
        }
        return AstraHttpSession.Default;
    }

    public async Task<bool> IsAuthenticatedAsync(IUserIdentity userIdentity, string sessionId)
        => await _identityDatabaseContext.ActiveSessions.AnyAsync(x => x.UserId == userIdentity.UserId && x.SessionId == sessionId);

    public async Task<IUserIdentity> CreateUserIdentityAsync(string username, [Optional] string emailAddress, [Optional] string password)
    {
        int newUserId = _identityDatabaseContext.Accounts.Count() + 1;
        var securityKeyPair = UserIdentityModel.CreateKeyPair();
        var userIdentity = new UserIdentityModel
        {
            UserId = newUserId,
            Uuid = Guid.NewGuid().ToString(),
            Username = username,
            Email = username,
            Fingerprint = securityKeyPair.fingerprint,
            PublicKey = securityKeyPair.pub,
            PrivateKey = securityKeyPair.priv,
            SecurityStamp = Hashing.SHA1(Guid.NewGuid().ToString() + DateTime.Now.Ticks),
            PasswordResetRequired = true,
            PasswordHash = string.Empty,
            Roles = ["user"],
        };
        
        if (!string.IsNullOrEmpty(password))
            userIdentity.PasswordHash = PasswordManager.HashPassword(password);
        await _identityDatabaseContext.Accounts.AddAsync(userIdentity);
        await _identityDatabaseContext.SaveChangesAsync();
        return userIdentity;
    }

    public async Task<LoginResponse> AttemptLoginAsync(string usernameOrEmail, string password, string grantType, string clientId)
    {
        var managedAccount = await _identityDatabaseContext.Accounts
            .FirstOrDefaultAsync(u => u.Username == usernameOrEmail || u.Email == usernameOrEmail);
        if (managedAccount == null)
            return LoginResponse.Failure(OAuthErrorCode.AccessDenied);

        if (!PasswordManager.ValidatePassword(password, managedAccount.PasswordHash))
            return LoginResponse.Failure(OAuthErrorCode.AccessDenied);

        var tokenGenerationResult = TokenManager.GenerateToken(managedAccount, clientId, out var sessionId);
        if (!tokenGenerationResult.success)
            return new LoginResponse
            {
                Error = tokenGenerationResult.error,
                ErrorDescription = tokenGenerationResult.errorDescription
            };

        await _identityDatabaseContext.ActiveSessions.AddAsync(new ActiveSession
        {
            SessionId = sessionId,
            UserId = managedAccount.UserId,
            AuthenticatedAt = DateTime.UtcNow,
            SessionType = SessionType.AuthenticatedViaPassword
        });
        await _identityDatabaseContext.SaveChangesAsync();

        return new LoginResponse
        {
            AccessToken = tokenGenerationResult.token,
            RefreshToken = Hashing.SHA1(managedAccount.SecurityStamp + DateTime.Now.Ticks + 2)
        };
    }

    public async Task<LoginResponse> AttemptLoginAsync(IUserIdentity userIdentity, string grantType, string clientId)
    {
        var managedAccount = await _identityDatabaseContext.Accounts
            .Include(u => u.ActiveSessions)
            .FirstOrDefaultAsync(u => u.UserId == userIdentity.UserId);
        
        if (managedAccount == null) 
            return LoginResponse.Failure(OAuthErrorCode.Unknown);
        
        var tokenGenerationResult = TokenManager.GenerateToken(managedAccount, clientId, out var sessionId);
        if (!tokenGenerationResult.success) 
            return new LoginResponse
            {
                Error = tokenGenerationResult.error, 
                ErrorDescription = tokenGenerationResult.errorDescription
            };

        await _identityDatabaseContext.ActiveSessions.AddAsync(new ActiveSession
        {
            SessionId = sessionId,
            UserId = managedAccount.UserId,
            AuthenticatedAt = DateTime.UtcNow,
            SessionType = SessionType.DirectlyAuthenticated
        });
        await _identityDatabaseContext.SaveChangesAsync();
        
        return new LoginResponse
        {
            AccessToken = tokenGenerationResult.token,
            RefreshToken = Hashing.SHA1(managedAccount.SecurityStamp + DateTime.Now.Ticks + 1)
        };
    }

    public async Task<bool> AttemptLogoutAsync(IUserIdentity userIdentity, string sessionId)
    {
        var managedAccount = await _identityDatabaseContext.Accounts
            .Include(u => u.ActiveSessions)
            .FirstOrDefaultAsync(u => u.UserId == userIdentity.UserId);
        if (managedAccount == null) 
            return false;
        
        managedAccount.ActiveSessions.RemoveAll(x => x.SessionId == sessionId);
        await _identityDatabaseContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> ValidatePasswordAsync(IUserIdentity userIdentity, string passwordUnhashed)
    {
        var managedAccount = await _identityDatabaseContext.Accounts.FindAsync(userIdentity.UserId);
        if (managedAccount == null) 
            return false;
        return PasswordManager.ValidatePassword(passwordUnhashed, managedAccount.PasswordHash);
    }

    public async Task<bool> ResetPasswordAsync(IUserIdentity userIdentity, bool requirePasswordReset)
    {
        var managedAccount = await _identityDatabaseContext.Accounts
            .Include(u => u.ActiveSessions)
            .FirstOrDefaultAsync(u => u.UserId == userIdentity.UserId);
        if (managedAccount == null) 
            return false;

        managedAccount.PasswordResetRequired = requirePasswordReset;
        managedAccount.PasswordHash = PasswordManager.GeneratePassword(7, PasswordCharacterSets.Letters | PasswordCharacterSets.Numbers);
        
        managedAccount.ActiveSessions.RemoveAll(x => x.UserId == userIdentity.UserId);
        await _identityDatabaseContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> AddTrustedDeviceAsync(IUserIdentity userIdentity, string name, string deviceId)
    {
        var managedAccount = await _identityDatabaseContext.Accounts
            .Include(u => u.TrustedDevices)
            .FirstOrDefaultAsync(u => u.UserId == userIdentity.UserId);
        if (managedAccount == null) return false;

        await _identityDatabaseContext.TrustedDevices.AddAsync(new TrustedDevice
        {
            TrustId = Guid.NewGuid().ToString(),
            Name = name + " (Trusted by Identity Server)",
            DeviceId = deviceId,
            TrustedAt = DateTime.UtcNow,
            UserId = managedAccount.UserId
        });
        
        await _identityDatabaseContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> RemoveTrustedDeviceAsync(IUserIdentity userIdentity, string trustId)
    {
        var managedAccount = await _identityDatabaseContext.Accounts
            .Include(u => u.TrustedDevices)
            .FirstOrDefaultAsync(u => u.UserId == userIdentity.UserId);
        if (managedAccount == null) return false;

        var trustedDevice = await _identityDatabaseContext.TrustedDevices.FindAsync(trustId);
        if (trustedDevice == null) return false;
        
        _identityDatabaseContext.TrustedDevices.Remove(trustedDevice);
        return true;
    }

    public async Task<bool> HasTrustedDeviceAsync(IUserIdentity userIdentity, string deviceId)
    {
        var managedAccount = await _identityDatabaseContext.Accounts
            .Include(u => u.TrustedDevices)
            .FirstOrDefaultAsync(u => u.UserId == userIdentity.UserId);
        if (managedAccount == null) return false;

        return await _identityDatabaseContext.TrustedDevices
            .AnyAsync(d => d.UserId == managedAccount.UserId && d.DeviceId == deviceId);
    }

    public IGrantTypeResponderRegistry GrantTypeRegistry => _responderRegistry;
}

//
// Auto-generated by JetBrains Rider
// To use this file in an application,
//  use: .AddSingleton<IAuthorizationService, AuthorizationService>();
//