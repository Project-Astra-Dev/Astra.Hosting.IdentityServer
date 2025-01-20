﻿using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Astra.Hosting.IdentityServer.Models;

public sealed class ActiveSession
{
    [Key] public string SessionId { get; set; }
    [ForeignKey("UserId")] public long UserId { get; set; }
    public DateTime AuthenticatedAt { get; set; }
}