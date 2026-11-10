using System.Security.Claims;
using System.Text;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using WebApi2026New.Models;

namespace WebApi2026New.Helpers
{
    // Esta clase se llena sola con los datos de la sección "Jwt" de appsettings.json
    public class JwtSettings
    {
        public string Key { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Audience { get; set; } = string.Empty;
        public int ExpiresMinutes { get; set; } = 60;
    }

    // La "fábrica" de tokens
    public class JwtHelper
    {
        private readonly JwtSettings _settings;

        public JwtHelper(IOptions<JwtSettings> options)
        {
            _settings = options.Value;
        }

        public (string token, DateTime expira) GenerarToken(Persona persona)
        {
            // 1. ¿Cuándo se vence? Ahora + los minutos de la configuración
            var expira = DateTime.UtcNow.AddMinutes(_settings.ExpiresMinutes);

            // 2. El PAYLOAD: los datos que viajan dentro del token. NUNCA la contraseña.
            var claims = new List<Claim>
            {
                new(JwtRegisteredClaimNames.Sub, persona.idPersona.ToString()),
                new(JwtRegisteredClaimNames.Email, persona.correo),
                new(JwtRegisteredClaimNames.Name, $"{persona.nombre} {persona.apellido}")
            };

            // 3. La clave secreta convertida en bytes
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_settings.Key));

            // 4. La "descripción" del token: datos, vencimiento, quién lo emite, para quién, y cómo se firma
            var descriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expira,
                Issuer = _settings.Issuer,
                Audience = _settings.Audience,
                SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            };

            // 5. Fabricar el token y devolverlo
            var token = new JsonWebTokenHandler().CreateToken(descriptor);
            return (token, expira);
        }
    }
}
