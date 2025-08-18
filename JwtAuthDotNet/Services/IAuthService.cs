using JwtAuthDotNet.DTOs;
using JwtAuthDotNet.Entities;

namespace JwtAuthDotNet.Services;

public interface IAuthService
{
    Task<User?> RegisterAsync(UserDto request);
    Task<TokenResponeDto?> LoginAsync(UserDto request);

    Task<TokenResponeDto?> RefreshTokensAsync(RefreshTokenRequestDto request);
}
