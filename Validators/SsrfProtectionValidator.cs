using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Internal;
using Guardrails.NET.Tools;

namespace Guardrails.NET.Validators;

/// <summary>
/// Configuration options for SsrfProtectionValidator.
/// </summary>
public sealed class SsrfProtectionOptions
{
    /// <summary>
    /// Whitelist of allowed domain names (supports wildcards like "*.openai.com"). If empty/null, all non-private domains are allowed.
    /// </summary>
    public IEnumerable<string>? AllowedDomains { get; set; }

    /// <summary>
    /// Blacklist of explicitly blocked domain names.
    /// </summary>
    public IEnumerable<string>? BlockedDomains { get; set; }

    /// <summary>
    /// Allowed URL schemes. Defaults to "https" and "http".
    /// </summary>
    public IEnumerable<string> AllowedSchemes { get; set; } = ["https", "http"];

    /// <summary>
    /// Blocks loopback, private RFC-1918, link-local, and cloud metadata (169.254.169.254) addresses. Defaults to true.
    /// </summary>
    public bool BlockPrivateIpAddresses { get; set; } = true;

    /// <summary>
    /// Argument parameter names to check for URLs.
    /// </summary>
    public IEnumerable<string> ArgumentNames { get; set; } =
    [
        "url", "uri", "endpoint", "targetUrl", "address", "href", "link", "webhook"
    ];
}

/// <summary>
/// Validates URLs against SSRF (Server-Side Request Forgery) attacks, private IP ranges, cloud metadata endpoints, and domain whitelists.
/// </summary>
public sealed class SsrfProtectionValidator : GuardValidatorBase, IToolCallValidator
{
    private static readonly TimeSpan DefaultRegexTimeout = TimeSpan.FromSeconds(1);
    private readonly SsrfProtectionOptions _options;
    private readonly List<Regex> _allowedDomainRegexes;
    private readonly List<Regex> _blockedDomainRegexes;
    private readonly HashSet<string> _allowedSchemes;
    private readonly string[] _cachedArgumentNames;

    public SsrfProtectionValidator(SsrfProtectionOptions? options = null)
    {
        _options = options ?? new SsrfProtectionOptions();
        _allowedDomainRegexes = (_options.AllowedDomains ?? Enumerable.Empty<string>())
            .Select(DomainPatternToRegex)
            .ToList();
        _blockedDomainRegexes = (_options.BlockedDomains ?? Enumerable.Empty<string>())
            .Select(DomainPatternToRegex)
            .ToList();
        _allowedSchemes = new HashSet<string>(_options.AllowedSchemes ?? ["https", "http"], StringComparer.OrdinalIgnoreCase);
        _cachedArgumentNames = _options.ArgumentNames?.ToArray() ?? [];
    }

    public override string Name => "SsrfProtectionValidator";

    public override Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, CancellationToken cancellationToken = default)
    {
        GuardHelper.ThrowIfNull(context);

        string? urlString = context.FindStringArgument(_cachedArgumentNames);
        if (string.IsNullOrWhiteSpace(urlString))
        {
            return Task.FromResult(GuardResult.Pass(context.FunctionName));
        }

        var violations = ValidateUrl(urlString!);
        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, urlString));
        }

        return Task.FromResult(GuardResult.Pass(urlString));
    }

    public override Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        var violations = ValidateUrl(content);
        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, content));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }

    private List<string> ValidateUrl(string urlString)
    {
        var violations = new List<string>();

        if (!Uri.TryCreate(urlString, UriKind.Absolute, out var uri))
        {
            violations.Add($"Malformed or invalid absolute URL: '{urlString}'.");
            return violations;
        }

        // 1. Check Allowed Schemes
        if (!_allowedSchemes.Contains(uri.Scheme))
        {
            violations.Add($"Prohibited URL scheme '{uri.Scheme}' in '{urlString}'. Allowed schemes: {string.Join(", ", _allowedSchemes)}.");
        }

        string host = uri.Host;

        // 2. Private IP / Localhost / Cloud Metadata Check
        if (_options.BlockPrivateIpAddresses)
        {
            if (IsPrivateOrRestrictedHost(host))
            {
                violations.Add($"Access to internal/private address, localhost, or cloud metadata endpoint '{host}' is blocked (SSRF Protection).");
            }
        }

        // 3. Blocked Domains Check
        foreach (var blocked in _blockedDomainRegexes)
        {
            if (blocked.IsMatch(host))
            {
                violations.Add($"Domain '{host}' is explicitly blocked by policy.");
                break;
            }
        }

        // 4. Allowed Domains Whitelist Check
        if (_allowedDomainRegexes.Count > 0)
        {
            bool isAllowed = _allowedDomainRegexes.Any(regex => regex.IsMatch(host));
            if (!isAllowed)
            {
                violations.Add($"Domain '{host}' is not in the approved domains whitelist.");
            }
        }

        return violations;
    }

    private static bool IsPrivateOrRestrictedHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) ||
            string.Equals(host, "127.0.0.1") ||
            string.Equals(host, "::1") ||
            string.Equals(host, "0.0.0.0"))
        {
            return true;
        }

        if (IPAddress.TryParse(host, out var ip))
        {
            if (IPAddress.IsLoopback(ip)) return true;

            byte[] bytes = ip.GetAddressBytes();

            // IPv4 Private Ranges & Cloud Metadata
            if (bytes.Length == 4)
            {
                // 10.0.0.0/8
                if (bytes[0] == 10) return true;

                // 172.16.0.0/12
                if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return true;

                // 192.168.0.0/16
                if (bytes[0] == 192 && bytes[1] == 168) return true;

                // 169.254.0.0/16 (Link-local & AWS/GCP/Azure Instance Metadata 169.254.169.254)
                if (bytes[0] == 169 && bytes[1] == 254) return true;

                // 0.0.0.0
                if (bytes[0] == 0) return true;
            }
            else if (bytes.Length == 16)
            {
                // IPv6 Link-Local / Unique Local
                if (ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal) return true;
            }
        }

        return false;
    }

    private static Regex DomainPatternToRegex(string domainPattern)
    {
        string pattern = Regex.Escape(domainPattern)
            .Replace(@"\*", "[a-zA-Z0-9_-]+");

        return new Regex($"^{pattern}$", RegexOptions.Compiled | RegexOptions.IgnoreCase, DefaultRegexTimeout);
    }
}
