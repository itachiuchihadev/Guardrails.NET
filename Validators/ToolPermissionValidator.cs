using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Internal;
using Guardrails.NET.Tools;

namespace Guardrails.NET.Validators;

/// <summary>
/// Enforces Role-Based Access Control (RBAC) and permissions on tool/function invocations.
/// </summary>
public sealed class ToolPermissionValidator : GuardValidatorBase, IToolCallValidator
{
    private readonly HashSet<string>? _allowedTools;
    private readonly HashSet<string>? _blockedTools;
    private readonly Func<string, bool>? _permissionChecker;

    public ToolPermissionValidator(
        IEnumerable<string>? allowedTools = null,
        IEnumerable<string>? blockedTools = null,
        Func<string, bool>? permissionChecker = null)
    {
        _allowedTools = allowedTools != null ? new HashSet<string>(allowedTools, StringComparer.OrdinalIgnoreCase) : null;
        _blockedTools = blockedTools != null ? new HashSet<string>(blockedTools, StringComparer.OrdinalIgnoreCase) : null;
        _permissionChecker = permissionChecker;
    }

    public override string Name => "ToolPermissionValidator";

    public override Task<GuardResult> ValidateToolCallAsync(ToolCallContext context, CancellationToken cancellationToken = default)
    {
        GuardHelper.ThrowIfNull(context);

        string funcName = context.FunctionName;

        // 1. Check blocked tools
        if (_blockedTools != null && _blockedTools.Contains(funcName))
        {
            return Task.FromResult(GuardResult.Fail(
                [$"Tool '{funcName}' is blocked by security permissions policy."],
                funcName));
        }

        // 2. Check allowed tools whitelist
        if (_allowedTools != null && !_allowedTools.Contains(funcName))
        {
            return Task.FromResult(GuardResult.Fail(
                [$"Tool '{funcName}' is not in the list of allowed tools."],
                funcName));
        }

        // 3. Custom dynamic permission check
        if (_permissionChecker != null && !_permissionChecker(funcName))
        {
            return Task.FromResult(GuardResult.Fail(
                [$"User or agent does not have permission to execute tool '{funcName}'."],
                funcName));
        }

        return Task.FromResult(GuardResult.Pass(funcName));
    }

    public override Task<GuardResult> ValidateAsync(string content, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(content))
        {
            return Task.FromResult(GuardResult.Pass(content));
        }

        string funcName = content.Trim();

        if (_blockedTools != null && _blockedTools.Contains(funcName))
        {
            return Task.FromResult(GuardResult.Fail(
                [$"Tool '{funcName}' is blocked by security permissions policy."],
                funcName));
        }

        if (_allowedTools != null && !_allowedTools.Contains(funcName))
        {
            return Task.FromResult(GuardResult.Fail(
                [$"Tool '{funcName}' is not in the list of allowed tools."],
                funcName));
        }

        if (_permissionChecker != null && !_permissionChecker(funcName))
        {
            return Task.FromResult(GuardResult.Fail(
                [$"User or agent does not have permission to execute tool '{funcName}'."],
                funcName));
        }

        return Task.FromResult(GuardResult.Pass(funcName));
    }
}

