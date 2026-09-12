using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Guardrails.NET.Internal;

internal static class GuardHelper
{
    public static void ThrowIfNull([NotNull] object? argument, [CallerArgumentExpression(nameof(argument))] string? paramName = null)
    {
        if (argument is null)
        {
            throw new ArgumentNullException(paramName);
        }
    }

    public static void ThrowIfNullOrWhiteSpace([NotNull] string? argument, [CallerArgumentExpression(nameof(argument))] string? paramName = null)
    {
        if (argument is null || string.IsNullOrWhiteSpace(argument))
        {
            throw new ArgumentException("Value cannot be null or whitespace.", paramName);
        }
    }

    /// <summary>
    /// Extracts a string representation from various argument types, including <see cref="string"/>, <see cref="System.Text.Json.JsonElement"/>, and primitive objects.
    /// </summary>
    public static bool TryExtractString(object? value, [NotNullWhen(true)] out string? result)
    {
        if (value is null)
        {
            result = null;
            return false;
        }

        if (value is string str)
        {
            result = str;
            return true;
        }

        if (value is System.Text.Json.JsonElement jsonElement)
        {
            switch (jsonElement.ValueKind)
            {
                case System.Text.Json.JsonValueKind.String:
                    result = jsonElement.GetString();
                    return result != null;
                case System.Text.Json.JsonValueKind.Null:
                case System.Text.Json.JsonValueKind.Undefined:
                    result = null;
                    return false;
                default:
                    result = jsonElement.GetRawText();
                    return !string.IsNullOrWhiteSpace(result);
            }
        }

        result = value.ToString();
        return result != null;
    }
}
