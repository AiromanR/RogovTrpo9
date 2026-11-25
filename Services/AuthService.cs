using Azure.Core;
using Microsoft.EntityFrameworkCore;
using RogovTRPO8.Models;
using System.Security.Cryptography;
using static RogovTRPO8.Models.DTOs;

namespace RogovTRPO8.Services
{
    static public class AuthService
    {
        static private readonly RogovDbContext _db = DBService.Instance.Context;

        static public List<User> GetUsersFromDb()
        {
            return _db.Users.ToList();
        }
        static public void UserSaveToDb(User user)
        {
            _db.Users.Add(user);
            _db.SaveChanges();
        }
        static public void RefreshTokenSaveToDb(byte[] randomBytes, int userId)
        {
            _db.RefreshTokens.Add(new RefreshToken
            {
                UserId = userId,
                TokenHash = HashToken(Convert.ToBase64String(randomBytes)),
                ExpiresAt = DateTime.UtcNow.AddDays(7)
            });
            _db.SaveChanges();
        }
        private static string HashToken(string token) => Convert.ToBase64String(SHA256.HashData(Convert.FromBase64String(token)));

        static public RefreshToken? RefreshTokenExist(RefreshRequest request)
        {
            try
            {
                var hash = HashToken(request.refresh_token);

                return _db.RefreshTokens.Include(r => r.User).FirstOrDefault(r => r.TokenHash == hash);
            }
            catch (Exception)
            {
                return null;
            }
        }
        static public void RefreshTokenRemove(RefreshToken existing)
        {
            _db.RefreshTokens.Remove(existing);
            _db.SaveChanges();                            
        }
        static public RevokedToken RefreshTokenRemoveWithRevoke(RefreshToken existing, string jti, DateTime expiresAt)
        {
            _db.RefreshTokens.Remove(existing);
            var revTo = _db.RevokedTokens.Add(new RevokedToken { Jti = jti, ExpiresAt = expiresAt });
            _db.SaveChanges();
            return revTo.Entity;
        }
        static public bool RevokeTokenGet(string jti)
        {
            return _db.RevokedTokens.Any(x => x.Jti == jti);
        }
        static public void CheckTokens()
        {
            foreach (var token in _db.RevokedTokens)
            {
                if (token.ExpiresAt < DateTime.UtcNow)
                    _db.RevokedTokens.Remove(token);
            }
            foreach (var token in _db.RefreshTokens)
            {
                if (token.ExpiresAt < DateTime.UtcNow)
                    _db.RefreshTokens.Remove(token);
            }
            _db.SaveChanges();
        }
    }
}
