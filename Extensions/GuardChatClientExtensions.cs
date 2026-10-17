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
using Microsoft.Extensions.Logging;

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
/// Owns the tool invocation loop: validates each LLM-requested tool call with the ToolGuardrailPipeline
/// before executing it, and injects FunctionResultContent feedback into the conversation so the model
/// can self-correct when a tool call is blocked.
/// </summary>
public sealed class GuardedChatClient : DelegatingChatClient
{
    private readonly GuardPipeline? _inputPipeline;
    private readonly GuardPipeline? _outputPipeline;
    private readonly ToolGuardrailPipeline? _toolPipeline;
    private readonly string? _systemGuidance;
    private readonly GuardChatClientOptions _options;
    private readonly ILogger? _logger;

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

        var logger = _options.Logger ?? _options.LoggerFactory?.CreateLogger("Guardrails.NET");
        var toolsLogger = _options.LoggerFactory?.CreateLogger("Guardrails.NET.Tools") ?? logger;
        var pipelineLogger = _options.LoggerFactory?.CreateLogger("Guardrails.NET.Pipeline") ?? logger;

        _logger = logger;

        if (_inputPipeline != null && _inputPipeline.Logger == null)
            _inputPipeline.Logger = pipelineLogger;
        if (_outputPipeline != null && _outputPipeline.Logger == null)
            _outputPipeline.Logger = pipelineLogger;
        if (_toolPipeline != null && _toolPipeline.Logger == null)
            _toolPipeline.Logger = toolsLogger;
    }

    // -------------------------------------------------------------------------
    // GetResponseAsync — owns the full tool invocation loop
    // -------------------------------------------------------------------------

    public override async Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        var messagesList = PrepareMessages(chatMessages);

        // 1. Guard Input
        var (guardedMessages, inputFallback) = await GuardInputMessagesAsync(messagesList, cancellationToken);
        if (inputFallback != null)
        {
            if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                _logger.LogWarning("Input guardrail triggered fallback. Short-circuiting LLM execution: {Fallback}", inputFallback);
            return new ChatResponse(new ChatMessage(ChatRole.Assistant, inputFallback));
        }
        messagesList = guardedMessages ?? messagesList;

        // 2. Tool invocation loop with per-call validation
        for (int turn = 0; turn < _options.MaxToolTurns; turn++)
        {
            // Call the raw inner LLM (not FunctionInvokingChatClient — we own the loop)
            var response = await base.GetResponseAsync(messagesList, options, cancellationToken);

            // Collect all function calls from this LLM turn
            var functionCalls = response.Messages
                .Where(m => m.Contents != null)
                .SelectMany(m => m.Contents!)
                .OfType<FunctionCallContent>()
                .ToList();

            if (functionCalls.Count == 0)
            {
                // No tool calls — guard the output text and return the final answer
                return await GuardOutputAsync(response, cancellationToken);
            }

            if (_logger != null && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Turn {Turn}: LLM requested {Count} tool call(s).", turn + 1, functionCalls.Count);

            // Add this assistant turn (which contains FunctionCallContent) to conversation history
            messagesList.AddRange(response.Messages);

            // Validate and execute (or block) each function call
            var toolResults = new List<AIContent>();
            bool shortCircuit = false;
            string? shortCircuitMsg = null;

            foreach (var functionCall in functionCalls)
            {
                var (toolResult, fallbackToUser) = await HandleFunctionCallAsync(
                    functionCall, options, cancellationToken);

                if (fallbackToUser != null)
                {
                    shortCircuit = true;
                    shortCircuitMsg = fallbackToUser;
                    break;
                }

                toolResults.Add(toolResult!);
            }

            if (shortCircuit)
            {
                if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning("Tool guardrail triggered user-facing fallback. Short-circuiting.");
                return new ChatResponse(new ChatMessage(ChatRole.Assistant, shortCircuitMsg!))
                {
                    ModelId = response.ModelId
                };
            }

            // Inject all tool results as a Tool-role message and loop back to the LLM
            messagesList.Add(new ChatMessage(ChatRole.Tool, toolResults));
        }

        // MaxToolTurns exceeded — return a graceful message instead of looping forever
        if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
            _logger.LogWarning("GuardedChatClient exceeded MaxToolTurns ({Max}). Returning graceful fallback.", _options.MaxToolTurns);
        return new ChatResponse(new ChatMessage(ChatRole.Assistant,
            "I was unable to complete this request within the allowed number of steps."));
    }

    // -------------------------------------------------------------------------
    // GetStreamingResponseAsync — buffers tool turns, streams only final text turn
    // -------------------------------------------------------------------------

    public override async IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        var messagesList = PrepareMessages(chatMessages);

        // 1. Guard Input
        var (guardedMessages, inputFallback) = await GuardInputMessagesAsync(messagesList, cancellationToken);
        if (inputFallback != null)
        {
            if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                _logger.LogWarning("Input guardrail triggered streaming fallback: {Fallback}", inputFallback);
            yield return new ChatResponseUpdate(ChatRole.Assistant, inputFallback);
            yield break;
        }
        messagesList = guardedMessages ?? messagesList;

        // 2. Tool invocation loop
        for (int turn = 0; turn < _options.MaxToolTurns; turn++)
        {
            // Buffer this turn's streaming updates so we can inspect for function calls.
            // Tool-call turns are always buffered; only the final text turn is actually streamed.
            var updates = new List<ChatResponseUpdate>();
            await foreach (var update in base.GetStreamingResponseAsync(messagesList, options, cancellationToken)
                .WithCancellation(cancellationToken))
            {
                updates.Add(update);
            }

            // Collect unique FunctionCallContent by CallId.
            // In streaming, the same function call may appear across multiple update chunks
            // (partial argument streaming), so we keep the first complete occurrence per CallId.
            var functionCallsById = new Dictionary<string, FunctionCallContent>(StringComparer.OrdinalIgnoreCase);
            var assistantContents = new List<AIContent>();

            foreach (var update in updates)
            {
                if (update.Contents == null) continue;
                foreach (var content in update.Contents)
                {
                    if (content is FunctionCallContent fc)
                    {
                        if (!functionCallsById.ContainsKey(fc.CallId))
                        {
                            functionCallsById[fc.CallId] = fc;
                            assistantContents.Add(fc);
                        }
                    }
                    else
                    {
                        assistantContents.Add(content);
                    }
                }
            }

            var functionCalls = functionCallsById.Values.ToList();

            if (functionCalls.Count == 0)
            {
                // No tool calls — apply output guard and stream the updates to the caller
                await foreach (var guardedUpdate in GuardStreamingUpdatesAsync(updates, cancellationToken))
                    yield return guardedUpdate;
                yield break;
            }

            if (_logger != null && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Streaming turn {Turn}: {Count} tool call(s) detected — buffering.", turn + 1, functionCalls.Count);

            // Add this assistant turn (with FunctionCallContent) to conversation history
            if (assistantContents.Count > 0)
                messagesList.Add(new ChatMessage(ChatRole.Assistant, assistantContents));

            // Validate and execute (or block) each function call
            var toolResults = new List<AIContent>();
            bool shortCircuit = false;
            string? shortCircuitMsg = null;

            foreach (var functionCall in functionCalls)
            {
                var (toolResult, fallbackToUser) = await HandleFunctionCallAsync(
                    functionCall, options, cancellationToken);

                if (fallbackToUser != null)
                {
                    shortCircuit = true;
                    shortCircuitMsg = fallbackToUser;
                    break;
                }

                toolResults.Add(toolResult!);
            }

            if (shortCircuit)
            {
                if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning("Tool guardrail triggered streaming user-facing fallback.");
                yield return new ChatResponseUpdate(ChatRole.Assistant, shortCircuitMsg!);
                yield break;
            }

            // Inject tool results as a Tool-role message and loop back to the LLM
            messagesList.Add(new ChatMessage(ChatRole.Tool, toolResults));
        }

        // MaxToolTurns exceeded
        if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
            _logger.LogWarning("GuardedChatClient exceeded MaxToolTurns ({Max}) in streaming. Returning graceful fallback.", _options.MaxToolTurns);
        yield return new ChatResponseUpdate(ChatRole.Assistant,
            "I was unable to complete this request within the allowed number of steps.");
    }

    // -------------------------------------------------------------------------
    // HandleFunctionCallAsync — validate then execute or inject security feedback
    // -------------------------------------------------------------------------

    /// <summary>
    /// Validates a single function call against the ToolGuardrailPipeline, then either:
    /// executes the real tool and returns its FunctionResultContent, injects a security-error
    /// FunctionResultContent so the model can self-correct, or returns a user-facing fallback.
    /// </summary>
    private async Task<(AIContent? ToolResult, string? FallbackToUser)> HandleFunctionCallAsync(
        FunctionCallContent functionCall,
        ChatOptions? options,
        CancellationToken cancellationToken)
    {
        // 1. Validate with ToolGuardrailPipeline (if configured)
        if (_toolPipeline != null)
        {
            var context = new ToolCallContext(functionCall.Name, functionCall.Arguments, functionCall.CallId);
            var validation = await _toolPipeline.ValidateAsync(context, cancellationToken);

            if (!validation.IsValid)
            {
                if (_toolPipeline.FailAction == OnToolFailAction.BlockAndThrow)
                {
                    if (_logger != null && _logger.IsEnabled(LogLevel.Error))
                        _logger.LogError("Tool '{FunctionName}' blocked — throwing GuardViolationException. Violations: {Violations}",
                            functionCall.Name, string.Join("; ", validation.Violations));
                    throw new GuardViolationException(
                        $"Tool '{functionCall.Name}' violated safety policy: {string.Join("; ", validation.Violations)}",
                        validation.Violations.ToList());
                }

                if (_toolPipeline.FailAction == OnToolFailAction.ReturnFallbackToUser)
                {
                    if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                        _logger.LogWarning("Tool '{FunctionName}' blocked — returning fallback to user.", functionCall.Name);
                    return (null, _toolPipeline.FallbackMessage);
                }

                if (_toolPipeline.FailAction == OnToolFailAction.ReturnFeedbackToModel)
                {
                    // Inject the security error as FunctionResultContent matched by CallId.
                    // The LLM receives this as its tool result and can self-correct accordingly.
                    var feedbackMsg = context.CustomResult?.ToString()
                        ?? $"[Security Error]: Tool '{functionCall.Name}' was blocked. " +
                           $"Violations: {string.Join("; ", validation.Violations)}";

                    if (_logger != null && _logger.IsEnabled(LogLevel.Information))
                        _logger.LogInformation(
                            "Injecting security feedback for '{FunctionName}' (CallId: {CallId}) as FunctionResultContent for model self-correction.",
                            functionCall.Name, functionCall.CallId);

                    return (new FunctionResultContent(functionCall.CallId, feedbackMsg), null);
                }
            }
        }

        // 2. Validation passed (or no pipeline) — find and execute the actual tool
        var tool = FindTool(options, functionCall.Name);

        if (tool == null)
        {
            if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                _logger.LogWarning("Tool '{FunctionName}' (CallId: {CallId}) not found in ChatOptions.Tools.",
                    functionCall.Name, functionCall.CallId);
            return (new FunctionResultContent(functionCall.CallId,
                $"Tool '{functionCall.Name}' is not available."), null);
        }

        try
        {
            if (_logger != null && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Executing tool '{FunctionName}' (CallId: {CallId}).", functionCall.Name, functionCall.CallId);

            var args = functionCall.Arguments != null
                ? new AIFunctionArguments(functionCall.Arguments)
                : new AIFunctionArguments();

            var result = await tool.InvokeAsync(args, cancellationToken);

            if (_logger != null && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Tool '{FunctionName}' executed successfully.", functionCall.Name);

            return (new FunctionResultContent(functionCall.CallId, result), null);
        }
        catch (Exception ex)
        {
            if (_logger != null && _logger.IsEnabled(LogLevel.Error))
                _logger.LogError(ex, "Tool '{FunctionName}' threw an exception.", functionCall.Name);
            return (new FunctionResultContent(functionCall.CallId,
                $"Error executing '{functionCall.Name}': {ex.Message}"), null);
        }
    }

    /// <summary>Finds an AIFunction in ChatOptions.Tools by name (case-insensitive).</summary>
    private static AIFunction? FindTool(ChatOptions? options, string functionName) =>
        options?.Tools?
            .OfType<AIFunction>()
            .FirstOrDefault(t => string.Equals(t.Name, functionName, StringComparison.OrdinalIgnoreCase));

    // -------------------------------------------------------------------------
    // Output guard helpers
    // -------------------------------------------------------------------------

    private async Task<ChatResponse> GuardOutputAsync(ChatResponse response, CancellationToken cancellationToken)
    {
        if (_outputPipeline == null || string.IsNullOrEmpty(response.Text))
            return response;

        var result = await _outputPipeline.ValidateAsync(response.Text, cancellationToken);

        if (!result.IsValid && _outputPipeline.FailAction == OnFailAction.ReturnFallback)
        {
            if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                _logger.LogWarning("Output guardrail triggered fallback on response text.");
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

        return response;
    }

    private async IAsyncEnumerable<ChatResponseUpdate> GuardStreamingUpdatesAsync(
        List<ChatResponseUpdate> updates,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        foreach (var update in updates)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (_outputPipeline != null && !string.IsNullOrEmpty(update.Text))
            {
                var result = await _outputPipeline.ValidateAsync(update.Text, cancellationToken);

                if (!result.IsValid && _outputPipeline.FailAction == OnFailAction.ReturnFallback)
                {
                    if (_logger != null && _logger.IsEnabled(LogLevel.Warning))
                        _logger.LogWarning("Output guardrail triggered streaming fallback.");
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

    // -------------------------------------------------------------------------
    // Message preparation helpers (unchanged)
    // -------------------------------------------------------------------------

    private List<ChatMessage> PrepareMessages(IEnumerable<ChatMessage> chatMessages)
    {
        var list = chatMessages as List<ChatMessage> ?? chatMessages.ToList();
        return ApplySystemGuidance(list);
    }

    private List<ChatMessage> ApplySystemGuidance(List<ChatMessage> messages)
    {
        if (string.IsNullOrWhiteSpace(_systemGuidance))
            return messages;

        var result = new List<ChatMessage>(messages.Count + 1);
        bool injected = false;

        foreach (var msg in messages)
        {
            if (!injected && msg.Role == ChatRole.System)
            {
                if (msg.Text != null && msg.Text.Contains(_systemGuidance))
                {
                    result.Add(msg);
                }
                else
                {
                    string combined = $"{msg.Text}\n\n[Safety Context]: {_systemGuidance}";
                    result.Add(new ChatMessage(ChatRole.System, combined));
                }
                injected = true;
            }
            else
            {
                result.Add(msg);
            }
        }

        if (!injected)
            result.Insert(0, new ChatMessage(ChatRole.System, $"[Safety Context]: {_systemGuidance}"));

        return result;
    }

    private async Task<(List<ChatMessage>? GuardedMessages, string? FallbackMessage)> GuardInputMessagesAsync(
        List<ChatMessage> messagesList,
        CancellationToken cancellationToken)
    {
        if (_inputPipeline == null || messagesList.Count == 0)
            return (messagesList, null);

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
                            return (null, _inputPipeline.FallbackMessage);
                        if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                            guardedMessages[targetIndex] = new ChatMessage(msg.Role, result.SanitizedContent);
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
                        return (null, _inputPipeline.FallbackMessage);
                    if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                        guardedMessages[targetIndex] = new ChatMessage(msg.Role, result.SanitizedContent);
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
                            return (null, _inputPipeline.FallbackMessage);
                        if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                            guardedMessages[i] = new ChatMessage(msg.Role, result.SanitizedContent);
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
                            return (null, _inputPipeline.FallbackMessage);
                        if (_inputPipeline.FailAction == OnFailAction.Sanitize && result.SanitizedContent != null)
                            guardedMessages[i] = new ChatMessage(msg.Role, result.SanitizedContent);
                    }
                }
                break;
            }
        }

        return (guardedMessages, null);
    }
}

