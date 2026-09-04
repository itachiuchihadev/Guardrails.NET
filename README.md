# AIGuard.NET

Production safety guardrails, PII redaction, SQL/code injection detection, and content validation middleware for .NET and `Microsoft.Extensions.AI`.

`AIGuard.NET` protects enterprise AI applications by inspecting and sanitizing LLM inputs and outputs:
- **Zero-Allocation PII Redaction**: Detects and sanitizes emails, US SSNs, credit cards, and phone numbers.
- **SQL & Code Injection Detection**: Blocks dangerous SQL keywords, tautologies (`OR 1=1`), comments, and injection patterns.
- **Flexible Action Modes**: Supports `Sanitize` (auto-masking), `ThrowException` (strict gating), and `LogOnly` (audit mode).
- **Native `IChatClient` Middleware**: Wraps any `IChatClient` transparently via `client.UseGuard(inputPipeline, outputPipeline)`.

## Quick Start

```csharp
using AIGuard.NET.Pipeline;
using AIGuard.NET.Validators;
using AIGuard.NET.Extensions;
using Microsoft.Extensions.AI;

// 1. Configure guardrail pipelines
var inputPipeline = new GuardPipeline()
    .AddValidator(new NoPiiValidator())
    .AddValidator(new SqlInjectionValidator());
inputPipeline.FailAction = OnFailAction.Sanitize;

var outputPipeline = new GuardPipeline()
    .AddValidator(new ToxicWordValidator(new[] { "internal_credentials", "confidential" }));
outputPipeline.FailAction = OnFailAction.Sanitize;

// 2. Wrap your chat client
IChatClient chatClient = ...;
IChatClient guardedClient = chatClient.UseGuard(inputPipeline, outputPipeline);

// 3. Any PII in the prompt is redacted before sending to LLM,
//    and forbidden terms in LLM output are sanitized before returning!
var response = await guardedClient.GetResponseAsync("My email is user@domain.com");
```

## Standalone Pipeline Execution

You can also run guardrails independently anywhere in your application:

```csharp
var pipeline = new GuardPipeline();
pipeline.AddValidator(new NoPiiValidator());
pipeline.FailAction = OnFailAction.Sanitize;

var result = await pipeline.ValidateAsync("Please bill 4111-2222-3333-4444.");
if (!result.IsValid)
{
    Console.WriteLine("Violations: " + string.Join(", ", result.Violations));
    Console.WriteLine("Sanitized: " + result.SanitizedContent);
}
```

## License

MIT License.
