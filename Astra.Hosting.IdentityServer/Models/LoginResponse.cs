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
    TemporarilyUnavailable
}

public sealed class LoginResponse
{
    public static LoginResponse Success(string accessToken, string refreshToken)
    {
        return new LoginResponse
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    public static LoginResponse Failure(OAuthErrorCode errorCode)
    {
        return new LoginResponse
        {
            Error = errorCode.ToString(),
            ErrorDescription = GetErrorDescription(errorCode)
        };
    }

    public string? AccessToken { get; set; }
    public string? RefreshToken { get; set; }
    public string? Error { get; set; }
    public string? ErrorDescription { get; set; }

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
            _ => "An unknown error occurred."
        };
    }
}
