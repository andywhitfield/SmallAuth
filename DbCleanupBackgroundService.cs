using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SmallAuth.Models;

namespace SmallAuth;

public class DbCleanupBackgroundService : BackgroundService
{
    private readonly ILogger<DbCleanupBackgroundService> _logger;
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private static readonly TimeSpan _initialWaitPeriod = new(0, 0, 10);
    private static readonly TimeSpan _pollPeriod = new(1, 0, 0, 0); // once a day is more than enough
    private static readonly TimeSpan _tokenExpireTime = new(365, 0, 0, 0); // anything older than 1 year

    public DbCleanupBackgroundService(ILogger<DbCleanupBackgroundService> logger, IServiceScopeFactory serviceScopeFactory)
    {
        _logger = logger;
        _serviceScopeFactory = serviceScopeFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            _logger.LogDebug($"Waiting {_initialWaitPeriod} before running db cleanup");
            await Task.Delay(_initialWaitPeriod, stoppingToken);

            while (!stoppingToken.IsCancellationRequested)
            {
                using (var serviceScope = _serviceScopeFactory.CreateScope())
                {
                    var dbContext = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    var expireDate = DateTime.UtcNow.Subtract(_tokenExpireTime);
                    _logger.LogInformation($"Checking for tokens to remove older than: {expireDate}");
                    using var txn = await dbContext.Database.BeginTransactionAsync();
                    var deletedCount = await dbContext.Database.ExecuteSqlInterpolatedAsync($"delete from OpenIddictTokens where ExpirationDate < {expireDate}");
                    await txn.CommitAsync();
                    _logger.LogInformation($"Successfully deleted {deletedCount} expired tokens");
                }

                using (var serviceScope = _serviceScopeFactory.CreateScope())
                {
                    var dbContext = serviceScope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
                    var expireDate = DateTime.UtcNow.Subtract(_tokenExpireTime);
                    _logger.LogInformation($"Checking for authorizations to remove older than: {expireDate}");
                    using var txn = await dbContext.Database.BeginTransactionAsync();
                    var deletedCount = await dbContext.Database.ExecuteSqlInterpolatedAsync($"delete from OpenIddictAuthorizations where CreationDate is null or CreationDate < {expireDate}");
                    await txn.CommitAsync();
                    _logger.LogInformation($"Successfully deleted {deletedCount} expired authorizations");
                }

                _logger.LogDebug($"Waiting {_pollPeriod} before running db clean up check again");
                await Task.Delay(_pollPeriod, stoppingToken);
            }
        }
        catch (OperationCanceledException)
        {
            _logger.LogInformation("Service is stopping");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Unexpected error in db cleanup, background job failed.");
        }
    }
}
