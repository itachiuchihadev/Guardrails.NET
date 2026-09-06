namespace Guardrails.NET.Tools;

/// <summary>
/// Defines the action to take when a tool call violates a safety policy.
/// </summary>
public enum OnToolFailAction
{
    /// <summary>
    /// Feeds a safety error message back to the LLM as the tool result, allowing the model to self-correct. (Default)
    /// </summary>
    ReturnFeedbackToModel = 0,

    /// <summary>
    /// Blocks tool execution immediately and throws a <see cref="Guardrails.NET.Pipeline.GuardViolationException"/>.
    /// </summary>
    BlockAndThrow = 1,

    /// <summary>
    /// Short-circuits the conversation turn and returns a fallback message to the user.
    /// </summary>
    ReturnFallbackToUser = 2
}
