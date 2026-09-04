using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Guardrails.NET.Abstractions;
using Guardrails.NET.Extensions;
using Guardrails.NET.Pipeline;
using Guardrails.NET.Validators;
using Microsoft.Extensions.AI;
using Xunit;

namespace Guardrails.NET.Tests;

public class MockEchoChatClient : IChatClient
{
    public List<ChatMessage> ReceivedMessages { get; } = new();
    private readonly string _responseToReturn;

    public MockEchoChatClient(string responseToReturn = "Echo response")
    {
        _responseToReturn = responseToReturn;
    }

    public Task<ChatResponse> GetResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default)
    {
        ReceivedMessages.AddRange(chatMessages);
        return Task.FromResult(new ChatResponse(new ChatMessage(ChatRole.Assistant, _responseToReturn)));
    }

    public IAsyncEnumerable<ChatResponseUpdate> GetStreamingResponseAsync(
        IEnumerable<ChatMessage> chatMessages,
        ChatOptions? options = null,
        CancellationToken cancellationToken = default) => throw new NotImplementedException();

    public object? GetService(Type serviceType, object? serviceKey = null) => null;
    public void Dispose() { }
}

public class PipelineExecutionTests
{
    [Fact]
    public async Task Pipeline_ChainsMultipleValidatorsAndSanitizes()
    {
        var pipeline = new GuardPipeline();
        pipeline.AddValidator(new NoPiiValidator());
        pipeline.AddValidator(new ToxicWordValidator(new[] { "secret_key", "confidential" }));
        pipeline.FailAction = OnFailAction.Sanitize;

        string input = "User test@corp.com leaked confidential data.";
        var result = await pipeline.ValidateAsync(input);

        Assert.False(result.IsValid);
        Assert.Equal(2, result.Violations.Count);
        Assert.Equal("User [REDACTED_EMAIL] leaked [BLOCKED] data.", result.SanitizedContent);
    }

    [Fact]
    public async Task Pipeline_ThrowsExceptionWhenConfigured()
    {
        var pipeline = new GuardPipeline();
        pipeline.AddValidator(new SqlInjectionValidator());
        pipeline.FailAction = OnFailAction.ThrowException;

        await Assert.ThrowsAsync<GuardViolationException>(() =>
            pipeline.ValidateAsync("DROP TABLE Orders;--")
        );
    }

    [Fact]
    public async Task GuardedChatClient_SanitizesInputAndOutput()
    {
        var inputPipeline = new GuardPipeline();
        inputPipeline.AddValidator(new NoPiiValidator());
        inputPipeline.FailAction = OnFailAction.Sanitize;

        var outputPipeline = new GuardPipeline();
        outputPipeline.AddValidator(new ToxicWordValidator(new[] { "classified" }));
        outputPipeline.FailAction = OnFailAction.Sanitize;

        var mockClient = new MockEchoChatClient("This is classified internal information.");
        var guardedClient = mockClient.UseGuard(inputPipeline, outputPipeline);

        var response = await guardedClient.GetResponseAsync(
            new[] { new ChatMessage(ChatRole.User, "Email me at dev@test.com") });

        // Assert input was sanitized before reaching the model
        Assert.Equal("Email me at [REDACTED_EMAIL]", mockClient.ReceivedMessages.First().Text);

        // Assert output was sanitized before returning to caller
        Assert.Equal("This is [BLOCKED] internal information.", response.Text);
    }
}
