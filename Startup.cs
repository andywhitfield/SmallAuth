using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;
using SmallAuth.Models;

namespace SmallAuth
{
    public class Startup
    {
        public Startup(IConfiguration configuration) => Configuration = configuration;

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddMvc();

            services.AddAuthorization(options =>
            {
                options.AddPolicy("SuperUser", policy => policy.RequireClaim("urn:smallauth:user", "superuser"));
            });

            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlite(Configuration.GetConnectionString("SmallAuth"));
                options.UseOpenIddict();
            });

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            services.Configure<IdentityOptions>(options =>
            {
                options.ClaimsIdentity.UserNameClaimType = OpenIddictConstants.Claims.Name;
                options.ClaimsIdentity.UserIdClaimType = OpenIddictConstants.Claims.Subject;
                options.ClaimsIdentity.RoleClaimType = OpenIddictConstants.Claims.Role;

                options.Password.RequireDigit = false;
                options.Password.RequireLowercase = false;
                options.Password.RequireUppercase = false;
                options.Password.RequireNonAlphanumeric = false;
            });

            services.AddOpenIddict()
                .AddCore(options =>
                {
                    options.UseEntityFrameworkCore()
                           .UseDbContext<ApplicationDbContext>();
                })

                .AddServer(options =>
                {
                    options.SetAuthorizationEndpointUris("/connect/authorize")
                           .SetLogoutEndpointUris("/connect/logout")
                           .SetTokenEndpointUris("/connect/token")
                           .SetUserinfoEndpointUris("/connect/userinfo")
                           .SetVerificationEndpointUris("/connect/verify");

                    options.AllowAuthorizationCodeFlow().AllowPasswordFlow();

                    options.RegisterScopes(OpenIddictConstants.Scopes.Profile,
                                           OpenIddictConstants.Scopes.Roles);

                    options.AddDevelopmentEncryptionCertificate()
                           .AddDevelopmentSigningCertificate();

                    options.UseAspNetCore()
                           .EnableStatusCodePagesIntegration()
                           .EnableAuthorizationEndpointPassthrough()
                           .EnableLogoutEndpointPassthrough()
                           .EnableTokenEndpointPassthrough()
                           .EnableUserinfoEndpointPassthrough()
                           .EnableVerificationEndpointPassthrough()
                            // During development, you can disable the HTTPS requirement.
                           .DisableTransportSecurityRequirement();
                })

                .AddValidation(options =>
                {
                    options.AddAudiences("resource_server");
                    options.UseLocalServer();
                    options.UseAspNetCore();
                });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.EnvironmentName == "Development")
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseStatusCodePagesWithReExecute("/error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            // Note: ASP.NET Core is impacted by a bug that prevents the status code pages
            // from working correctly with endpoint routing. For more information, visit
            // https://github.com/aspnet/AspNetCore/issues/13715#issuecomment-528929683.
            app.Use((context, next) =>
            {
                context.SetEndpoint(null);
                return next();
            });

            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(options => options.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}"));

            using var scope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope();
            scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.EnsureCreated();
        }
    }
}
