using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Internal;
using Guardrails.NET.Tools;

namespace Guardrails.NET.Validators;

/// <summary>
/// Configuration options for FileAccessValidator.
/// </summary>
public sealed class FileAccessOptions
{
    /// <summary>
    /// Root directories within which file operations are permitted. If empty or null, directory sandboxing is disabled.
    /// </summary>
    public IEnumerable<string>? AllowedRoots { get; set; }

    /// <summary>
    /// File patterns that are protected from modification or access (e.g., "*.env", "appsettings*.json", "*.key", ".git/**").
    /// </summary>
    public IEnumerable<string> ProtectedPatterns { get; set; } =
    [
        "*.env",
        ".env*",
        "appsettings*.json",
        "*.key",
        "*.pem",
        "*.pfx",
        "*.config",
        ".git/**",
        ".git\\**"
    ];

    /// <summary>
    /// Allowed file extensions (e.g., ".cs", ".json", ".md", ".txt"). If null or empty, all extensions are permitted.
    /// </summary>
    public IEnumerable<string>? AllowedExtensions { get; set; }

    /// <summary>
    /// Names of tool arguments to inspect for file paths.
    /// </summary>
    public IEnumerable<string> ArgumentNames { get; set; } =
    [
        "path", "filePath", "targetFile", "file", "destination", "source", "filename", "targetPath", "relativePath"
    ];

    /// <summary>
    /// Keywords in tool function names that indicate write/destructive operations.
    /// </summary>
    public IEnumerable<string> WriteOperationKeywords { get; set; } =
    [
        "edit", "write", "create", "delete", "remove", "modify", "save", "overwrite", "update", "patch", "replace"
    ];

    /// <summary>
    /// Enforces read-only access by disallowing all write/destructive operations.
    /// </summary>
    public bool ReadOnly { get; set; } = false;

    /// <summary>
    /// Strictly disallows path traversal characters ('..' or parent directory referencing).
    /// </summary>
    public bool DisallowPathTraversal { get; set; } = true;
}

/// <summary>
/// Inspects file operations in tool calls to enforce directory sandboxing, path traversal defense, and protected file policies.
/// </summary>
public sealed class FileAccessValidator : GuardValidatorBase, IToolCallValidator
{
    private static readonly TimeSpan DefaultRegexTimeout = TimeSpan.FromSeconds(1);
    private readonly FileAccessOptions _options;
    private readonly List<Regex> _protectedPatternRegexes;
    private readonly string[] _cachedArgumentNames;

    public FileAccessValidator(FileAccessOptions? options = null)
    {
        _options = options ?? new FileAccessOptions();
        _protectedPatternRegexes = (_options.ProtectedPatterns ?? Enumerable.Empty<string>())
            .Select(GlobToRegex)
            .ToList();
        _cachedArgumentNames = _options.ArgumentNames?.ToArray() ?? [];
    }

    public override string Name => "FileAccessValidator";

    public override Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, CancellationToken cancellationToken = default)
    {
        GuardHelper.ThrowIfNull(context);

        string? filePath = context.FindStringArgument(_cachedArgumentNames);
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return Task.FromResult(GuardResult.Pass(context.FunctionName));
        }

        bool isWriteOperation = _options.ReadOnly || IsWriteFunction(context.FunctionName);
        var violations = ValidatePath(filePath!, isWriteOperation);

        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, filePath));
        }

        return Task.FromResult(GuardResult.Pass(filePath));
    }

    public override Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        var violations = ValidatePath(content, isWriteOperation: _options.ReadOnly);
        if (violations.Count > 0)
        {
            return Task.FromResult(GuardResult.Fail(violations, content));
        }

        return Task.FromResult(GuardResult.Pass(content));
    }

    private List<string> ValidatePath(string path, bool isWriteOperation)
    {
        var violations = new List<string>();

        // 1. Path Traversal Check
        if (_options.DisallowPathTraversal)
        {
            if (path.Contains("..") || path.Contains("%2e%2e", StringComparison.OrdinalIgnoreCase))
            {
                violations.Add($"Path traversal attempt detected in '{path}'.");
            }
        }

        // 2. Read-Only Restriction
        if (_options.ReadOnly && isWriteOperation)
        {
            violations.Add($"Write operation is prohibited in read-only mode for path '{path}'.");
        }

        // 3. Protected Pattern Matching
        string normalizedFileName = Path.GetFileName(path);
        string normalizedFullPath = path.Replace('\\', '/');

        foreach (var regex in _protectedPatternRegexes)
        {
            if (regex.IsMatch(normalizedFileName) || regex.IsMatch(normalizedFullPath) || regex.IsMatch(path))
            {
                violations.Add($"Access to protected file or pattern '{path}' is blocked by security policy.");
                break;
            }
        }

        // 4. Allowed Roots / Directory Sandboxing (Hardened against prefix traversal)
        if (_options.AllowedRoots != null && _options.AllowedRoots.Any())
        {
            bool withinAllowedRoot = false;
            try
            {
#if NETSTANDARD2_0
                string fullTarget = Path.GetFullPath(path);
                foreach (var root in _options.AllowedRoots)
                {
                    string fullRoot = Path.GetFullPath(root);
                    if (!fullRoot.EndsWith(Path.DirectorySeparatorChar.ToString()) && !fullRoot.EndsWith(Path.AltDirectorySeparatorChar.ToString()))
                    {
                        fullRoot += Path.DirectorySeparatorChar;
                    }
                    if (fullTarget.Equals(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase) ||
                        fullTarget.StartsWith(fullRoot, StringComparison.OrdinalIgnoreCase))
                    {
                        withinAllowedRoot = true;
                        break;
                    }
                }
#else
                string fullTarget = Path.GetFullPath(path);
                foreach (var root in _options.AllowedRoots)
                {
                    string fullRoot = Path.GetFullPath(root);
                    string rel = Path.GetRelativePath(fullRoot, fullTarget);
                    if (!rel.StartsWith("..", StringComparison.Ordinal) && !Path.IsPathRooted(rel))
                    {
                        withinAllowedRoot = true;
                        break;
                    }
                }
#endif
            }
            catch
            {
                withinAllowedRoot = false;
            }

            if (!withinAllowedRoot)
            {
                violations.Add($"Path '{path}' is outside permitted workspace roots.");
            }
        }

        // 5. Allowed Extensions
        if (_options.AllowedExtensions != null && _options.AllowedExtensions.Any())
        {
            string ext = Path.GetExtension(path);
            bool isAllowed = _options.AllowedExtensions.Any(allowed =>
                string.Equals(allowed.StartsWith(".") ? allowed : "." + allowed, ext, StringComparison.OrdinalIgnoreCase));

            if (!isAllowed)
            {
                violations.Add($"File extension '{ext}' in path '{path}' is not in the allowed extensions list.");
            }
        }

        return violations;
    }

    private bool IsWriteFunction(string functionName)
    {
        if (string.IsNullOrWhiteSpace(functionName)) return false;

        return _options.WriteOperationKeywords.Any(kw =>
            functionName.Contains(kw, StringComparison.OrdinalIgnoreCase));
    }

    private static Regex GlobToRegex(string glob)
    {
        string pattern = Regex.Escape(glob)
            .Replace(@"\*\*", ".*")
            .Replace(@"\*", "[^/\\\\]*")
            .Replace(@"\?", ".");

        return new Regex($"^{pattern}$", RegexOptions.Compiled | RegexOptions.IgnoreCase, DefaultRegexTimeout);
    }
}
