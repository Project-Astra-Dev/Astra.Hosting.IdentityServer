using System.Text.Json.Serialization;

namespace Astra.Hosting.IdentityServer.Models;

public enum OAuthErrorCode 
{
    Unknown = -1,
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    UnauthorizedClient,
    UnsupportedGrantType,
    InvalidScope,
    AccessDenied,
    ServerError,
    TemporarilyUnavailable,
    MfaRequired,
    MfaCodeInvalid,
    MfaCodeExpired,
    BiometricAuthRequired,
    BiometricAuthFailed,
    HardwareTokenRequired,
    HardwareTokenInvalid,
    SmsVerificationRequired,
    SmsVerificationFailed,
    EmailVerificationRequired,
    EmailVerificationFailed,
    AccountLocked,
    AccountDisabled,
    PasswordExpired,
    PasswordChangeRequired,
    DeviceNotTrusted,
    LocationNotTrusted,
    RiskDetected,
    SessionExpired,
    ConcurrentLoginDetected,
    IPBlocked
}

public sealed class LoginResponse
{
    public static LoginResponse Success(string accessToken, string refreshToken, string sessionId)
    {
        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            SessionId = sessionId
        };
    }

    public static LoginResponse Failure(OAuthErrorCode errorCode)
    {
        return new LoginResponse
        {
            Error = GetErrorCode(errorCode),
            ErrorDescription = GetErrorDescription(errorCode)
        };
    }

    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }
    public string SessionId { get; set; }
    
    public bool IsSuccess => string.IsNullOrEmpty(Error) && string.IsNullOrEmpty(ErrorDescription) && !string.IsNullOrEmpty(AccessToken) && !string.IsNullOrEmpty(SessionId);

    private static string GetErrorCode(OAuthErrorCode errorCode)
    {
        return errorCode switch
        {
            OAuthErrorCode.InvalidRequest => "invalid_request",
            OAuthErrorCode.InvalidClient => "invalid_client",
            OAuthErrorCode.InvalidGrant => "invalid_grant",
            OAuthErrorCode.UnauthorizedClient => "unauthorized_client",
            OAuthErrorCode.UnsupportedGrantType => "unsupported_grant",
            OAuthErrorCode.InvalidScope => "invalid_scope",
            OAuthErrorCode.AccessDenied => "access_denied",
            OAuthErrorCode.ServerError => "server_error",
            OAuthErrorCode.TemporarilyUnavailable => "temporarily_unavailable",
            OAuthErrorCode.MfaRequired => "mfa_required",
            OAuthErrorCode.MfaCodeInvalid => "mfa_code_invalid",
            OAuthErrorCode.MfaCodeExpired => "mfa_code_expired",
            OAuthErrorCode.BiometricAuthRequired => "biometric_auth_required",
            OAuthErrorCode.BiometricAuthFailed => "biometric_auth_failed",
            OAuthErrorCode.HardwareTokenRequired => "hardware_token_required",
            OAuthErrorCode.HardwareTokenInvalid => "hardware_token_invalid",
            OAuthErrorCode.SmsVerificationRequired => "sms_verification_required",
            OAuthErrorCode.SmsVerificationFailed => "sms_verification_failed",
            OAuthErrorCode.EmailVerificationRequired => "email_verification_required",
            OAuthErrorCode.EmailVerificationFailed => "email_verification_failed",
            OAuthErrorCode.AccountLocked => "account_locked",
            OAuthErrorCode.AccountDisabled => "account_disabled",
            OAuthErrorCode.PasswordExpired => "password_expired",
            OAuthErrorCode.PasswordChangeRequired => "password_change_required",
            OAuthErrorCode.DeviceNotTrusted => "untrusted_device",
            OAuthErrorCode.LocationNotTrusted => "untrusted_location",
            OAuthErrorCode.RiskDetected => "risk_detected",
            OAuthErrorCode.SessionExpired => "session_expired",
            OAuthErrorCode.ConcurrentLoginDetected => "concurrent_login_detected",
            OAuthErrorCode.IPBlocked => "ip_blocked",
            _ => "An unknown error occurred."
        };
    }

    private static string GetErrorDescription(OAuthErrorCode errorCode)
    {
        return errorCode switch
        {
            OAuthErrorCode.InvalidRequest => 
                "The request is missing a required parameter, includes an invalid parameter value, or is otherwise malformed.",
            OAuthErrorCode.InvalidClient => 
                "Client authentication failed. This could be due to an unknown client, invalid client credentials, or unsupported authentication method.",
            OAuthErrorCode.InvalidGrant => 
                "The provided authorization grant (e.g., authorization code, resource owner credentials) is invalid, expired, or revoked.",
            OAuthErrorCode.UnauthorizedClient => 
                "The client is not authorized to request an authorization code using this method.",
            OAuthErrorCode.UnsupportedGrantType => 
                "The authorization grant type is not supported by the authorization server.",
            OAuthErrorCode.InvalidScope => 
                "The requested scope is invalid, unknown, or exceeds what the client is authorized to request.",
            OAuthErrorCode.AccessDenied => 
                "The resource owner or authorization server denied the request.",
            OAuthErrorCode.ServerError => 
                "The authorization server encountered an error and could not complete the request. Please try again later.",
            OAuthErrorCode.TemporarilyUnavailable => 
                "The authorization server is temporarily unavailable due to maintenance or overload. Please try again later.",
            OAuthErrorCode.MfaRequired => 
                "Multi-factor authentication is required to complete this login.",
            OAuthErrorCode.MfaCodeInvalid => 
                "The provided multi-factor authentication code is invalid.",
            OAuthErrorCode.MfaCodeExpired => 
                "The multi-factor authentication code has expired. Please request a new code.",
            OAuthErrorCode.BiometricAuthRequired => 
                "Biometric authentication is required to complete this login.",
            OAuthErrorCode.BiometricAuthFailed => 
                "Biometric authentication failed. Please try again or use an alternative authentication method.",
            OAuthErrorCode.HardwareTokenRequired => 
                "A hardware security token is required to complete this login.",
            OAuthErrorCode.HardwareTokenInvalid => 
                "The provided hardware token response is invalid.",
            OAuthErrorCode.SmsVerificationRequired => 
                "SMS verification is required to complete this login.",
            OAuthErrorCode.SmsVerificationFailed => 
                "SMS verification failed. Please try again or request a new code.",
            OAuthErrorCode.EmailVerificationRequired => 
                "Email verification is required to complete this login.",
            OAuthErrorCode.EmailVerificationFailed => 
                "Email verification failed. Please try again or request a new verification email.",
            OAuthErrorCode.AccountLocked => 
                "Your account has been locked due to multiple failed login attempts. Please contact support.",
            OAuthErrorCode.AccountDisabled => 
                "This account has been disabled. Please contact your administrator.",
            OAuthErrorCode.PasswordExpired => 
                "Your password has expired and must be changed before proceeding.",
            OAuthErrorCode.PasswordChangeRequired => 
                "You must change your password before proceeding.",
            OAuthErrorCode.DeviceNotTrusted => 
                "This device is not recognized. Additional verification is required.",
            OAuthErrorCode.LocationNotTrusted => 
                "Login attempt from an unusual location detected. Additional verification is required.",
            OAuthErrorCode.RiskDetected => 
                "Suspicious activity detected. Additional verification is required.",
            OAuthErrorCode.SessionExpired => 
                "Your session has expired. Please log in again.",
            OAuthErrorCode.ConcurrentLoginDetected => 
                "Another active session was detected. Multiple concurrent sessions are not allowed.",
            OAuthErrorCode.IPBlocked => 
                "Access from this IP address has been blocked due to suspicious activity.",
            _ => "An unknown error occurred."
        };
    }
}
