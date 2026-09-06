namespace Guardrails.NET.Extensions;

/// <summary>
/// Specifies which messages in the chat history should be evaluated by the input guard pipeline.
/// </summary>
public enum GuardValidationScope
{
    /// <summary>
    /// Validates only the latest user message in the conversation history. (Default)
    /// </summary>
    LatestUserMessageOnly = 0,

    /// <summary>
    /// Validates only the latest message in the conversation history, regardless of role.
    /// </summary>
    LatestMessageOnly = 1,

    /// <summary>
    /// Validates all user messages in the conversation history.
    /// </summary>
    AllUserMessages = 2,

    /// <summary>
    /// Validates all messages in the conversation history (User, Assistant, System).
    /// </summary>
    AllMessages = 3
}

/// <summary>
/// Configuration options for GuardedChatClient.
/// </summary>
public class GuardChatClientOptions
{
    /// <summary>
    /// Gets or sets the scope of input messages to validate. Defaults to <see cref="GuardValidationScope.LatestUserMessageOnly"/>.
    /// </summary>
    public GuardValidationScope ValidationScope { get; set; } = GuardValidationScope.LatestUserMessageOnly;
}
