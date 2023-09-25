using Azure.Core;
using Azure.Core.Pipeline;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Mvc;

namespace LowKey.API.Controllers;

[ApiController]
[Route("[controller]")]
public class SecretsController : ControllerBase
{
    
    private readonly ILogger<SecretsController> _logger;
    private SecretClient _secretClient;

    public SecretsController(ILogger<SecretsController> logger)
    {
        _logger = logger;
        var options = new SecretClientOptions(SecretClientOptions.ServiceVersion.V7_4)
        {
            DisableChallengeResourceVerification = true
        };
        _secretClient = new SecretClient(new Uri("https://localhost:8443/"),  new NoopCredentials(), GetClientOptions(options));
    }

    [HttpPost]
    [Route("SetSecret")]
    public IActionResult Post(string name, string value)
    {
        _secretClient.SetSecret(name, value);
        return Ok();
    }
    
    [HttpPost]
    [Route("GetSecret")]
    public IActionResult Post(string name)
    {
        var secret = _secretClient.GetSecret(name);
        return Ok(secret.Value);
    }
     
    
    
    private T GetClientOptions<T>(T options) where T : ClientOptions
    {
        DisableSslValidationOnClientOptions(options);
        return options;
    }

    /// <summary>
    /// Disables server certification callback.
    /// <br/>
    /// <b>WARNING: Do not use in production environments.</b>
    /// </summary>
    /// <param name="options"></param>
    private void DisableSslValidationOnClientOptions(ClientOptions options)
    {
        HttpClientHandler clientHandler = new HttpClientHandler();
        clientHandler.ServerCertificateCustomValidationCallback = (sender, cert, chain, sslPolicyErrors) => { return true; };
        options.Transport = new HttpClientTransport(clientHandler);
    }
}

/// <summary>
/// Allows us to bypass authentication when using Lowkey Vault.
/// <br/>
/// <b>WARNING: Will not work with real Azure services.</b>
/// </summary>
public class NoopCredentials: TokenCredential
{
    public override async ValueTask<AccessToken> GetTokenAsync(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return GetToken(requestContext, cancellationToken);
    }

    public override AccessToken GetToken(TokenRequestContext requestContext, CancellationToken cancellationToken)
    {
        return new AccessToken("noop", DateTimeOffset.MaxValue);
    }
}