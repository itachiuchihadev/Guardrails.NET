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

    /// <summary>
    /// Maximum number of tool-call / self-correction turns the guarded client will attempt
    /// per request before returning a graceful fallback. Defaults to 10.
    /// Mirrors <c>FunctionInvokingChatClient.MaximumIterationsPerRequest</c> semantics.
    /// </summary>
    public int MaxToolTurns { get; set; } = 10;


    /// <summary>
    /// Gets or sets an optional logger for recording guardrail evaluations and security events.
    /// </summary>
    public Microsoft.Extensions.Logging.ILogger? Logger { get; set; }

    /// <summary>
    /// Gets or sets an optional logger factory to create categorized loggers for different guardrail components.
    /// </summary>
    public Microsoft.Extensions.Logging.ILoggerFactory? LoggerFactory { get; set; }

    /// <summary>
    /// Fluent helper to configure a logger.
    /// </summary>
    public GuardChatClientOptions WithLogger(Microsoft.Extensions.Logging.ILogger logger)
    {
        Logger = logger;
        return this;
    }

    /// <summary>
    /// Fluent helper to configure a logger factory.
    /// </summary>
    public GuardChatClientOptions WithLoggerFactory(Microsoft.Extensions.Logging.ILoggerFactory loggerFactory)
    {
        LoggerFactory = loggerFactory;
        return this;
    }
}
