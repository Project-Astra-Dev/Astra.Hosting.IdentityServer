using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Astra.Hosting.IdentityServer.Models;

public sealed class TrustedDevice
{
    [Key] public string TrustId { get; set; }
    [ForeignKey("UserId")] public long UserId { get; set; }
    public string Name { get; set; }
    public string DeviceId { get; set; }
    public DateTime TrustedAt { get; set; }
    public TimeSpan Expiry { get; set; }
}