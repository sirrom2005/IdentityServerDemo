using IdentityServerDemo;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
// Add services to the container.
builder.Services.AddControllersWithViews();

// Add Identity Server
builder.Services.AddIdentityServer()
    .AddInMemoryClients(Config.Clients)
    .AddInMemoryApiScopes(Config.ApiScopes)
    .AddInMemoryIdentityResources(Config.IdentityResources)
    .AddTestUsers(Config.TestUsers)
    .AddDeveloperSigningCredential(); // For development only - use proper key in production

builder.Logging.AddConsole();
builder.Logging.AddDebug();
builder.Logging.SetMinimumLevel(LogLevel.Debug);
builder.Services.AddHttpClient();


var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Add Identity Server middleware
app.UseIdentityServer();

app.UseAuthorization();

app.MapRazorPages();
app.MapControllers();
app.Run();
