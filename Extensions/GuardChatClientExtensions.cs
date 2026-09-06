using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Internal;
using Guardrails.NET.Pipeline;
using Guardrails.NET.Tools;
using Microsoft.Extensions.AI;

namespace Guardrails.NET.Extensions;

/// <summary>
/// Extension methods for attaching guardrails and safety steering to IChatClient instances.
/// </summary>
public static class GuardChatClientExtensions
{

    public static IChatClient UseGuard(
        this IChatClient innerClient,
        GuardPipeline? inputPipeline = null,
        GuardPipeline? outputPipeline = null,
        ToolGuardrailPipeline? toolPipeline = null,
        string? systemGuidance = null,
        GuardChatClientOptions? options = null)
    {
        GuardHelper.ThrowIfNull(innerClient);
        return new GuardedChatClient(innerClient, inputPipeline, outputPipeline, toolPipeline, systemGuidance, options);
    }

    public static IChatClient UseGuard(
        this IChatClient innerClient,
        GuardPipeline? inputPipeline,
        GuardPipeline? outputPipeline,
        string? systemGuidance,
        GuardChatClientOptions? options = null)
    {
        GuardHelper.ThrowIfNull(innerClient);
        return new GuardedChatClient(innerClient, inputPipeline, outputPipeline, null, systemGuidance, options);
    }

    public static IChatClient UseGuard(
        this IChatClient innerClient,
        Action<GuardChatClientOptions> configureOptions,
        GuardPipeline? inputPipeline = null,
        GuardPipeline? outputPipeline = null,
        ToolGuardrailPipeline? toolPipeline = null,
        string? systemGuidance = null)
    {
        GuardHelper.ThrowIfNull(innerClient);
        GuardHelper.ThrowIfNull(configureOptions);
        var options = new GuardChatClientOptions();
        configureOptions(options);
        return new GuardedChatClient(innerClient, inputPipeline, outputPipeline, toolPipeline, systemGuidance, options);
    }

    public static IChatClient UseToolGuards(
        this IChatClient innerClient,
        ToolGuardrailPipeline toolPipeline,
        GuardChatClientOptions? options = null)
    {
        GuardHelper.ThrowIfNull(innerClient);
        GuardHelper.ThrowIfNull(toolPipeline);
        return new GuardedChatClient(innerClient, toolPipeline: toolPipeline, options: options);
    }
}

/// <summary>
/// Wraps an IChatClient with input, output, and tool GuardPipelines and optional system safety guidance.
/// </summary>
public sealed class GuardedChatClient : DelegatingChatClient
{
    private readonly GuardPipeline? _inputPipeline;
    private readonly GuardPipeline? _outputPipeline;
    private readonly ToolGuardrailPipeline? _toolPipeline;
    private readonly string? _systemGuidance;
    private readonly GuardChatClientOptions _options;
    private readonly IList<AITool> _aiTools;

    public GuardedChatClient(
        IChatClient innerClient,
        GuardPipeline? inputPipeline = null,
        GuardPipeline? outputPipeline = null,
        ToolGuardrailPipeline? toolPipeline = null,
        string? systemGuidance = null,
        GuardChatClientOptions? options = null)
        : base(innerClient)
    {
        _inputPipeline = inputPipeline;
        _outputPipeline = outputPipeline;
        _toolPipeline = toolPipeline;
        _systemGuidance = systemGuidance;
        _options = options ?? new GuardChatClientOptions();

        var tools = new List<AITool>();
        if (_options.ToolValidators != null)
        {
            foreach (var validator in _options.ToolValidators)
            {
                if (validator != null)
                {
                    tools.Add(validator.AsAITool());
                }
            }
        }
        if (_options.CustomTools != null)
        {
            foreach (var tool in _options.CustomTools)
            {
                if (tool != null)
                {
                    tools.Add(tool);
                }
            }
        }
        _aiTools = tools;
    }

    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messagesList = PrepareMessages(chatMessages);

        // 1. Guard Input
        var (guardedMessages, fallback) = await GuardInputMessagesAsync(messagesList, cancellationToken);
        if (fallback != null)
        {
            // Short-circuit: Do NOT call inner LLM
            return new ChatResponse(new ChatMessage(ChatRole.Assistant, fallback));
        }

        messagesList = guardedMessages ?? messagesList;

        // 2. Execute Inner Client with effective tools
        var effectiveOptions = ResolveEffectiveChatOptions(options);
        var response = await base.GetResponseAsync(messagesList, effectiveOptions, cancellationToken);

        // 3. Guard Tool Calls (if response requested function calls)
        if (_toolPipeline != null)
        {
            var toolFallback = await GuardToolCallsAsync(response, cancellationToken);
            if (toolFallback != null)
            {
                return new ChatResponse(new ChatMessage(ChatRole.Assistant, toolFallback))
                {
                    ResponseId = response.ResponseId,
                    ModelId = response.ModelId
                };
            }
        }

        // 4. Guard Output Text
        if (_outputPipeline != null && !string.IsNullOrEmpty(response.Text))
        {
            var result = await _outputPipeline.ValidateAsync(response.Text, cancellationToken);
            if (!result.IsValid && _outputPipeline.FailAction == OnFailAction.ReturnFallback)
            {
                return new ChatResponse(new ChatMessage(ChatRole.Assistant, _outputPipeline.FallbackMessage))
                {
                    ResponseId = response.ResponseId,
                    ModelId = response.ModelId
                };
            }

            if (_outputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
            {
                return new ChatResponse(new ChatMessage(ChatRole.Assistant, result.SanitizedContent))
                {
                    ResponseId = response.ResponseId,
                    ModelId = response.ModelId
                };
            }
        }

        return response;
    }

    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var messagesList = PrepareMessages(chatMessages);

        // 1. Guard Input
        var (guardedMessages, fallback) = await GuardInputMessagesAsync(messagesList, cancellationToken);
        if (fallback != null)
        {
            yield return new ChatResponseUpdate(ChatRole.Assistant, fallback);
            yield break;
        }

        messagesList = guardedMessages ?? messagesList;

        // 2. Stream and Guard Output
        var effectiveOptions = ResolveEffectiveChatOptions(options);
        await foreach (var update in base.GetStreamingResponseAsync(messagesList, effectiveOptions, cancellationToken).WithCancellation(cancellationToken))
        {
            if (_toolPipeline != null && update.Contents != null)
            {
                foreach (var functionCall in update.Contents.OfType<FunctionCallContent>())
                {
                    var context = new ToolCallContext(functionCall.Name, functionCall.Arguments, functionCall.CallId);
                    var result = await _toolPipeline.ValidateAsync(context, cancellationToken);
                    if (!result.IsValid && _toolPipeline.FailAction == OnToolFailAction.ReturnFallbackToUser)
                    {
                        yield return new ChatResponseUpdate(ChatRole.Assistant, _toolPipeline.FallbackMessage);
                        yield break;
                    }
                }
            }

            if (_outputPipeline != null && !string.IsNullOrEmpty(update.Text))
            {
                var result = await _outputPipeline.ValidateAsync(update.Text, cancellationToken);
                if (!result.IsValid && _outputPipeline.FailAction == OnFailAction.ReturnFallback)
                {
                    yield return new ChatResponseUpdate(ChatRole.Assistant, _outputPipeline.FallbackMessage);
                    yield break;
                }

                if (_outputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                {
                    yield return new ChatResponseUpdate(update.Role, result.SanitizedContent)
                    {
                        ResponseId = update.ResponseId,
                        ModelId = update.ModelId
                    };
                    continue;
                }
            }

            yield return update;
        }
    }

    private async Task<string?> GuardToolCallsAsync(ChatResponse response, CancellationToken cancellationToken)
    {
        if (_toolPipeline == null || response.Messages == null)
        {
            return null;
        }

        foreach (var msg in response.Messages)
        {
            if (msg.Contents == null) continue;

            for (int i = 0; i < msg.Contents.Count; i++)
            {
                if (msg.Contents[i] is FunctionCallContent functionCall)
                {
                    var context = new ToolCallContext(functionCall.Name, functionCall.Arguments, functionCall.CallId);
                    var result = await _toolPipeline.ValidateAsync(context, cancellationToken);

                    if (!result.IsValid)
                    {
                        if (_toolPipeline.FailAction == OnToolFailAction.ReturnFallbackToUser)
                        {
                            return _toolPipeline.FallbackMessage;
                        }
                    }
                }
            }
        }

        return null;
    }

    private List<ChatMessage> PrepareMessages(IEnumerable<ChatMessage> chatMessages)
    {
        var list = chatMessages as List<ChatMessage> ?? chatMessages.ToList();
        return ApplySystemGuidance(list);
    }

    private List<ChatMessage> ApplySystemGuidance(List<ChatMessage> messages)
    {
        if (string.IsNullOrWhiteSpace(_systemGuidance))
        {
            return messages;
        }

        var result = new List<ChatMessage>(messages.Count + 1);
        bool injected = false;

        foreach (var msg in messages)
        {
            if (!injected && msg.Role == ChatRole.System)
            {
                string combined = $"{msg.Text}\n\n[Safety Context]: {_systemGuidance}";
                result.Add(new ChatMessage(ChatRole.System, combined));
                injected = true;
            }
            else
            {
                result.Add(msg);
            }
        }

        if (!injected)
        {
            result.Insert(0, new ChatMessage(ChatRole.System, $"[Safety Context]: {_systemGuidance}"));
        }

        return result;
    }

    private async Task<(List<ChatMessage>? GuardedMessages, string? FallbackMessage)> GuardInputMessagesAsync(
        List<ChatMessage> messagesList,
        CancellationToken cancellationToken)
    {
        if (_inputPipeline == null || messagesList.Count == 0)
        {
            return (messagesList, null);
        }

        var guardedMessages = new List<ChatMessage>(messagesList);

        switch (_options.ValidationScope)
        {
            case GuardValidationScope.LatestUserMessageOnly:
            {
                int targetIndex = guardedMessages.FindLastIndex(m => m.Role == ChatRole.User);
                if (targetIndex >= 0)
                {
                    var msg = guardedMessages[targetIndex];
                    if (!string.IsNullOrEmpty(msg.Text))
                    {
                        var result = await _inputPipeline.ValidateAsync(msg.Text, cancellationToken);
                        if (!result.IsValid && _inputPipeline.FailAction == OnFailAction.ReturnFallback)
                        {
                            return (null, _inputPipeline.FallbackMessage);
                        }

                        if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                        {
                            guardedMessages[targetIndex] = new ChatMessage(msg.Role, result.SanitizedContent);
                        }
                    }
                }
                break;
            }

            case GuardValidationScope.LatestMessageOnly:
            {
                int targetIndex = guardedMessages.Count - 1;
                var msg = guardedMessages[targetIndex];
                if (!string.IsNullOrEmpty(msg.Text))
                {
                    var result = await _inputPipeline.ValidateAsync(msg.Text, cancellationToken);
                    if (!result.IsValid && _inputPipeline.FailAction == OnFailAction.ReturnFallback)
                    {
                        return (null, _inputPipeline.FallbackMessage);
                    }

                    if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                    {
                        guardedMessages[targetIndex] = new ChatMessage(msg.Role, result.SanitizedContent);
                    }
                }
                break;
            }

            case GuardValidationScope.AllUserMessages:
            {
                for (int i = 0; i < guardedMessages.Count; i++)
                {
                    var msg = guardedMessages[i];
                    if (msg.Role == ChatRole.User && !string.IsNullOrEmpty(msg.Text))
                    {
                        var result = await _inputPipeline.ValidateAsync(msg.Text, cancellationToken);
                        if (!result.IsValid && _inputPipeline.FailAction == OnFailAction.ReturnFallback)
                        {
                            return (null, _inputPipeline.FallbackMessage);
                        }

                        if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                        {
                            guardedMessages[i] = new ChatMessage(msg.Role, result.SanitizedContent);
                        }
                    }
                }
                break;
            }

            case GuardValidationScope.AllMessages:
            {
                for (int i = 0; i < guardedMessages.Count; i++)
                {
                    var msg = guardedMessages[i];
                    if (!string.IsNullOrEmpty(msg.Text))
                    {
                        var result = await _inputPipeline.ValidateAsync(msg.Text, cancellationToken);
                        if (!result.IsValid && _inputPipeline.FailAction == OnFailAction.ReturnFallback)
                        {
                            return (null, _inputPipeline.FallbackMessage);
                        }

                        if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                        {
                            guardedMessages[i] = new ChatMessage(msg.Role, result.SanitizedContent);
                        }
                    }
                }
                break;
            }
        }

        return (guardedMessages, null);
    }

    private ChatOptions? ResolveEffectiveChatOptions(ChatOptions? requestOptions)
    {
        if (_aiTools.Count == 0)
        {
            return requestOptions;
        }

        if (requestOptions == null)
        {
            return new ChatOptions { Tools = _aiTools };
        }

        if (requestOptions.Tools == null || requestOptions.Tools.Count == 0)
        {
            var cloned = requestOptions.Clone();
            cloned.Tools = _aiTools;
            return cloned;
        }

        var mergedTools = new List<AITool>(_aiTools.Count + requestOptions.Tools.Count);
        var seenNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var tool in requestOptions.Tools)
        {
            if (tool != null && seenNames.Add(tool.Name))
            {
                mergedTools.Add(tool);
            }
        }

        foreach (var tool in _aiTools)
        {
            if (tool != null && seenNames.Add(tool.Name))
            {
                mergedTools.Add(tool);
            }
        }

        var result = requestOptions.Clone();
        result.Tools = mergedTools;
        return result;
    }
}

