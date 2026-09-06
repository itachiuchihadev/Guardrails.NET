using System.Collections.Generic;
using Guardrails.NET.Abstractions;
using Microsoft.Extensions.AI;

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
    /// Gets or sets the validators to automatically convert into <see cref="AITool"/> instances and inject into every request's <see cref="ChatOptions.Tools"/>.
    /// </summary>
    public IList<IGuardValidator> ToolValidators { get; set; } = new List<IGuardValidator>();

    /// <summary>
    /// Gets or sets custom <see cref="AITool"/> instances to inject into every request's <see cref="ChatOptions.Tools"/>.
    /// </summary>
    public IList<AITool> CustomTools { get; set; } = new List<AITool>();

    /// <summary>
    /// Fluent helper to add a validator as an AI tool.
    /// </summary>
    public GuardChatClientOptions AddTool(IGuardValidator validator)
    {
        if (validator != null)
        {
            ToolValidators.Add(validator);
        }
        return this;
    }

    /// <summary>
    /// Fluent helper to add multiple validators as AI tools.
    /// </summary>
    public GuardChatClientOptions AddTools(params IGuardValidator[] validators)
    {
        if (validators != null)
        {
            for (int i = 0; i < validators.Length; i++)
            {
                if (validators[i] != null)
                {
                    ToolValidators.Add(validators[i]);
                }
            }
        }
        return this;
    }

    /// <summary>
    /// Fluent helper to add a custom AI tool.
    /// </summary>
    public GuardChatClientOptions AddTool(AITool tool)
    {
        if (tool != null)
        {
            CustomTools.Add(tool);
        }
        return this;
    }

    /// <summary>
    /// Fluent helper to add multiple custom AI tools.
    /// </summary>
    public GuardChatClientOptions AddTools(params AITool[] tools)
    {
        if (tools != null)
        {
            for (int i = 0; i < tools.Length; i++)
            {
                if (tools[i] != null)
                {
                    CustomTools.Add(tools[i]);
                }
            }
        }
        return this;
    }
}

