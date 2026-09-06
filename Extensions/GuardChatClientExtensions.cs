using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Pipeline;
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
        string? systemGuidance = null,
        GuardChatClientOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(innerClient);
        return new GuardedChatClient(innerClient, inputPipeline, outputPipeline, systemGuidance, options);
    }

    public static IChatClient UseGuard(
        this IChatClient innerClient,
        Action<GuardChatClientOptions> configureOptions,
        GuardPipeline? inputPipeline = null,
        GuardPipeline? outputPipeline = null,
        string? systemGuidance = null)
    {
        ArgumentNullException.ThrowIfNull(innerClient);
        ArgumentNullException.ThrowIfNull(configureOptions);
        var options = new GuardChatClientOptions();
        configureOptions(options);
        return new GuardedChatClient(innerClient, inputPipeline, outputPipeline, systemGuidance, options);
    }
}

/// <summary>
/// Wraps an IChatClient with input and output GuardPipelines and optional system safety guidance.
/// </summary>
public sealed class GuardedChatClient : DelegatingChatClient
{
    private readonly GuardPipeline? _inputPipeline;
    private readonly GuardPipeline? _outputPipeline;
    private readonly string? _systemGuidance;
    private readonly GuardChatClientOptions _options;

    public GuardedChatClient(
        IChatClient innerClient,
        GuardPipeline? inputPipeline = null,
        GuardPipeline? outputPipeline = null,
        string? systemGuidance = null,
        GuardChatClientOptions? options = null)
        : base(innerClient)
    {
        _inputPipeline = inputPipeline;
        _outputPipeline = outputPipeline;
        _systemGuidance = systemGuidance;
        _options = options ?? new GuardChatClientOptions();
    }

    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messagesList = ApplySystemGuidance(chatMessages.ToList());

        // 1. Guard Input
        var (guardedMessages, fallback) = await GuardInputMessagesAsync(messagesList, cancellationToken);
        if (fallback != null)
        {
            // Short-circuit: Do NOT call inner LLM
            return new ChatResponse(new ChatMessage(ChatRole.Assistant, fallback));
        }

        messagesList = guardedMessages ?? messagesList;

        // 2. Execute Inner Client
        var response = await base.GetResponseAsync(messagesList, options, cancellationToken);

        // 3. Guard Output
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
        var messagesList = ApplySystemGuidance(chatMessages.ToList());

        // 1. Guard Input
        var (guardedMessages, fallback) = await GuardInputMessagesAsync(messagesList, cancellationToken);
        if (fallback != null)
        {
            yield return new ChatResponseUpdate(ChatRole.Assistant, fallback);
            yield break;
        }

        messagesList = guardedMessages ?? messagesList;

        // 2. Stream and Guard Output
        await foreach (var update in base.GetStreamingResponseAsync(messagesList, options, cancellationToken).WithCancellation(cancellationToken))
        {
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
}
