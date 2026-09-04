using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AIGuard.NET.Pipeline;
using Microsoft.Extensions.AI;

namespace AIGuard.NET.Extensions;

/// <summary>
/// Extension methods for attaching guardrails to IChatClient instances.
/// </summary>
public static class GuardChatClientExtensions
{
    public static IChatClient UseGuard(
        this IChatClient innerClient,
        GuardPipeline? inputPipeline = null,
        GuardPipeline? outputPipeline = null)
    {
        ArgumentNullException.ThrowIfNull(innerClient);
        return new GuardedChatClient(innerClient, inputPipeline, outputPipeline);
    }
}

/// <summary>
/// Wraps an IChatClient with input and output GuardPipelines.
/// </summary>
public sealed class GuardedChatClient : DelegatingChatClient
{
    private readonly GuardPipeline? _inputPipeline;
    private readonly GuardPipeline? _outputPipeline;

    public GuardedChatClient(
        IChatClient innerClient,
        GuardPipeline? inputPipeline = null,
        GuardPipeline? outputPipeline = null)
        : base(innerClient)
    {
        _inputPipeline = inputPipeline;
        _outputPipeline = outputPipeline;
    }

    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messagesList = chatMessages.ToList();

        // 1. Guard Input
        if (_inputPipeline != null)
        {
            var guardedMessages = new List<ChatMessage>();
            foreach (var msg in messagesList)
            {
                if (!string.IsNullOrEmpty(msg.Text))
                {
                    var result = await _inputPipeline.ValidateAsync(msg.Text, cancellationToken);
                    if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                    {
                        guardedMessages.Add(new ChatMessage(msg.Role, result.SanitizedContent));
                        continue;
                    }
                }
                guardedMessages.Add(msg);
            }
            messagesList = guardedMessages;
        }

        // 2. Execute Inner Client
        var response = await base.GetResponseAsync(messagesList, options, cancellationToken);

        // 3. Guard Output
        if (_outputPipeline != null && !string.IsNullOrEmpty(response.Text))
        {
            var result = await _outputPipeline.ValidateAsync(response.Text, cancellationToken);
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
}
