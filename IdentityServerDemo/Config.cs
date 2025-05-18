using Duende.IdentityServer.Models;
using Duende.IdentityServer.Test;
using Duende.IdentityServer;
using System.Security.Claims;

namespace IdentityServerDemo
{
    public static class Config
    {
        public static IEnumerable<Client> Clients(IConfiguration configuration) =>
            new Client[]
            {
                new Client
                {
                    ClientId = "client",
                    AllowedGrantTypes = GrantTypes.ClientCredentials,
                    ClientSecrets =
                    {
                        new Secret(configuration["IdentityServer:Secret"].Sha256())
                    },
                    AllowedScopes = { "api1" }
                },
                 new Client
                {
                    ClientId = "id.server",
                    ClientSecrets = { new Secret(configuration["IdentityServer:Secret"].Sha256()) },
                    AllowedGrantTypes = GrantTypes.Code,
                    RequireConsent = false,
                    RequirePkce = true,
                    RedirectUris = { "https://localhost:7274/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:7274/signout-callback-oidc" },
                    AllowedScopes = new List<string>
                    {
                        "api1",
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email
                    }
                },
                new Client
                {
                    ClientId = "interactive.client",
                    ClientSecrets = { new Secret(configuration["IdentityServer:Secret"].Sha256()) },
                    AllowedGrantTypes = GrantTypes.ResourceOwnerPassword,
                    RequireConsent = false,
                    RedirectUris = { "https://localhost:7274/signin-oidc" },
                    PostLogoutRedirectUris = { "https://localhost:7274/signout-callback-oidc" },
                    AllowedScopes = new List<string>
                    {
                        "api1",
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email
                    }
                }
            };

        public static IEnumerable<ApiScope> ApiScopes =>
            new ApiScope[]
            {
                new ApiScope("api1", "My API")
            };

        public static IEnumerable<IdentityResource> IdentityResources =>
            new IdentityResource[]
            {
                new IdentityResources.OpenId(),
                new IdentityResources.Profile(),
                new IdentityResources.Email()
            };

        public static List<TestUser> TestUsers =>
        [
            new TestUser
            {
                SubjectId = "1",
                Username = "alice",
                Password = "alice",
                Claims =
                {
                    new Claim("name", "Alice"),
                    new Claim("website", "https://alice.com")
                }
            },
            new TestUser
            {
                SubjectId = "2",
                Username = "bob",
                Password = "bob",
                Claims =
                {
                    new Claim("name", "Bob"),
                    new Claim("website", "https://bob.com")
                }
            }
        ];
    }
}
