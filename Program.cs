using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using RogovTRPO8.Models;
using RogovTRPO8.Services;
using System.Collections.Concurrent;
using System.IdentityModel.Tokens.Jwt;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers( );
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer( );
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Введите JWT токен (без слова Bearer)."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});


builder.Services.AddSingleton<List<User>>();
builder.Services.AddSingleton<IPasswordHasher<User>, PasswordHasher<User>>();
var key = builder.Configuration ["Jwt:Key"] ?? throw new Exception("Не задан секретный ключ JWT");
if (Encoding.UTF8.GetByteCount(key) < 32) throw new Exception("Ключ JWT слишком короткий");
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).
    AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters {
            ValidateIssuer = true, 
            ValidIssuer = "ExampleApi", 

            ValidateAudience = true, 
            ValidAudience = "ExampleApiClient", 

            ValidateLifetime = true,

            ValidateIssuerSigningKey = true, 
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(key)
            ), 
            ClockSkew = TimeSpan.Zero 
        };
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated = context =>
            {
                // Получаем идентификатор проверенного JWT
                var jti = context.Principal?
                    .FindFirst(JwtRegisteredClaimNames.Jti)?.Value;

                if (string.IsNullOrEmpty(jti))
                {
                    context.Fail("В JWT отсутствует jti");
                    return System.Threading.Tasks.Task.CompletedTask;
                }

                if (AuthService.RevokeTokenGet(jti))
                    context.Fail("JWT отозван");

                return System.Threading.Tasks.Task.CompletedTask;
            }
        };
    });

var app = builder.Build( );

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment( ))
{
    app.UseSwagger( );
    app.UseSwaggerUI( );
}

app.UseHttpsRedirection( );

app.UseAuthorization( );

app.MapControllers( );

app.Run( );
