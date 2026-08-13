using System.Buffers;
using Microsoft.AspNetCore.Http;

namespace Fixture.ProjectPayments;

public static class ProjectPaymentWebhookBodyReader
{
    public const int MaxBodyBytes = 1024 * 1024;

    public static async ValueTask<byte[]?> TryReadAsync(
        HttpRequest request,
        CancellationToken cancellationToken = default)
    {
        if (request.ContentLength is > MaxBodyBytes)
            return null;

        var rented = ArrayPool<byte>.Shared.Rent(MaxBodyBytes + 1);
        try
        {
            var total = 0;
            while (total <= MaxBodyBytes)
            {
                var read = await request.Body.ReadAsync(
                    rented.AsMemory(total, MaxBodyBytes + 1 - total),
                    cancellationToken);
                if (read == 0)
                    return rented.AsSpan(0, total).ToArray();

                total += read;
            }

            return null;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rented, clearArray: true);
        }
    }
}
