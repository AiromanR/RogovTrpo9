using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using RogovTRPO8.Models;
using RogovTRPO8.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using static RogovTRPO8.Models.DTOs;
//Jwt key = ReplaceThisWithARandomSecretOfAtLeast32BytesRogov
namespace RogovTRPO8.Controllers
{
    [ApiController]
    [Route("api/v1/auth")]
    public class AuthController : ControllerBase
    {
        private readonly List<User> _users;
        private readonly IPasswordHasher<User> _hasher;
        private readonly IConfiguration _configuration;
        public AuthController(IPasswordHasher<User> hasher, IConfiguration configuration)
        {
            _users = AuthService.GetUsersFromDb();
            _hasher = hasher;
            _configuration = configuration;
        }

        [HttpPost("register")]
        public IActionResult Register(AuthRequest request)
        {
            if (_users.Any(u => u.Login == request.Login))
                return Conflict("Логин уже существует");
            var user = new User { Login = request.Login, Role = "User" };
            user.PasswordHash = _hasher.HashPassword(user, request.Password);
            _users.Add(user);
            AuthService.UserSaveToDb(user);
            return Ok("Пользователь зарегистрирован");
        }

        [HttpPost("login")]
        public IActionResult Login(AuthRequest request)
        {
            AuthService.CheckTokens();

            var user = _users.Find(u => u.Login == request.Login);

            if (user == null)
                return Unauthorized("Неверная пара логин/пароль");

            var result = _hasher.VerifyHashedPassword(
                user,
                user.PasswordHash,
                request.Password
            );

            if (result == PasswordVerificationResult.Failed)
                return Unauthorized("Неверная пара логин/пароль");

            var token = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken(user);

            return Ok(new
            {
                access_token = token, refresh_token = refreshToken
            });
        }

        [HttpPost("refresh")]
        public IActionResult Refresh(RefreshRequest request)
        {
            var existing = AuthService.RefreshTokenExist(request);
            if (existing == null || existing.ExpiresAt < DateTime.UtcNow)
                return Unauthorized();

            AuthService.RefreshTokenRemove(existing);

            var accessToken = GenerateJwtToken(existing.User);
            var refreshToken = GenerateRefreshToken(existing.User);

            return Ok(new { access_token = accessToken, refresh_token = refreshToken });
        }

        [HttpPost("logout")]
        [Authorize]
        public IActionResult Logout(RefreshRequest request)
        {
            var currentUser = User.Identity?.Name;
            var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            var expString = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;

            if (string.IsNullOrEmpty(currentUser) || string.IsNullOrEmpty(jti))
                return Unauthorized();

            var existing = AuthService.RefreshTokenExist(request);

            if (existing == null || existing.ExpiresAt < DateTime.UtcNow)
                return Unauthorized();

            if (existing.User.Login != currentUser)
                return Forbid();

            var expiresAt = DateTimeOffset.FromUnixTimeSeconds(long.Parse(expString)).UtcDateTime;

            AuthService.RefreshTokenRemoveWithRevoke(existing, jti, expiresAt);

            return NoContent();
        }
        private string GenerateJwtToken(User user)
        {
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, user.Login),
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]!));
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                issuer: "ExampleApi",
                audience: "ExampleApiClient",
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(1),
                signingCredentials: credentials

            );
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        private string GenerateRefreshToken(User user) //создаём и сохраняем в бд рефреш токен
        {
            var randomBytes = RandomNumberGenerator.GetBytes(32); //что-то типа 32 криптографических байт
            AuthService.RefreshTokenSaveToDb(randomBytes, user.Id); //всё в сервисе
            return Convert.ToBase64String(randomBytes); ; //переделываем байты во что-то что можно нормально сохранить
        }
    }
}