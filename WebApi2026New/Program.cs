using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Scalar.AspNetCore;
using WebApi2026New.Data;
using WebApi2026New.Helpers;

var builder = WebApplication.CreateBuilder(args);

// ===== BLOQUE A: Base de datos (esto ya lo tenías) =====
builder.Services.AddDbContext<AppDBContext>(options =>
{
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"));
});

// ===== BLOQUE B: JWT =====
// B1. Leer la sección "Jwt" de appsettings y registrar la fábrica de tokens
builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection("Jwt"));
builder.Services.AddSingleton<JwtHelper>();

var jwt = builder.Configuration.GetSection("Jwt").Get<JwtSettings>()
          ?? throw new InvalidOperationException("Falta la sección 'Jwt' en appsettings.json.");

// B2. Si la clave es muy corta, la API NO arranca (protección)
if (Encoding.UTF8.GetByteCount(jwt.Key) < 32)
    throw new InvalidOperationException("Jwt:Key debe tener al menos 32 caracteres.");

// B3. Contratar al PORTERO: le decimos qué revisar en cada token
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false; // conserva los nombres "sub", "email", "name"
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,               // ¿lo fabricó mi API?
            ValidIssuer = jwt.Issuer,
            ValidateAudience = true,             // ¿es para mis clientes?
            ValidAudience = jwt.Audience,
            ValidateLifetime = true,             // ¿está vencido?
            ClockSkew = TimeSpan.FromMinutes(1), // 1 minuto de tolerancia
            ValidateIssuerSigningKey = true,     // ¿la firma es auténtica?
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt.Key)),
            NameClaimType = "name"
        };
    });

builder.Services.AddAuthorization();

// ===== BLOQUE C: Controladores =====
builder.Services.AddControllers();

// ===== BLOQUE D: OpenAPI / Scalar =====
// Declara el esquema "Bearer" para que Scalar muestre DÓNDE pegar el token
builder.Services.AddOpenApi(options =>
{
    options.AddDocumentTransformer((document, context, cancellationToken) =>
    {
        document.Components ??= new OpenApiComponents();
        document.Components.SecuritySchemes ??= new Dictionary<string, IOpenApiSecurityScheme>();
        document.Components.SecuritySchemes["Bearer"] = new OpenApiSecurityScheme
        {
            Type = SecuritySchemeType.Http,
            Scheme = "bearer",
            BearerFormat = "JWT",
            Description = "Pega aquí el token que devuelve POST /api/Auth/login"
        };
        document.Security =
        [
            new OpenApiSecurityRequirement
            {
                [new OpenApiSecuritySchemeReference("Bearer", document)] = []
            }
        ];
        return Task.CompletedTask;
    });
});

var app = builder.Build();

// ===== BLOQUE E: El "pipeline": por dónde pasa cada petición, EN ORDEN =====
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.MapScalarApiReference(options =>
    {
        options.Title = "WebApi2026New";
        options.AddPreferredSecuritySchemes("Bearer"); // Scalar selecciona Bearer solo
    });
}

app.UseHttpsRedirection();

app.UseAuthentication(); // 1º ¿Quién eres?  (el portero lee la manilla)
app.UseAuthorization();  // 2º ¿Puedes pasar? (decide si te deja entrar)

app.MapControllers();

app.Run();