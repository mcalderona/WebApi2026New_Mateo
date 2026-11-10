using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using WebApi2026New.Data;
using WebApi2026New.DTOs;
using WebApi2026New.Helpers;
using WebApi2026New.Models;

// OJO: aquí NO va [Authorize] arriba de la clase.
// Si lo pusiéramos, necesitarías un token para hacer login... ¡y el token te lo da el login!
[Route("api/[controller]")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly AppDBContext _context; // acceso a la base de datos
    private readonly JwtHelper _jwt;        // la fábrica de tokens del Paso 4

    public AuthController(AppDBContext context, JwtHelper jwt)
    {
        _context = context;
        _jwt = jwt;
    }

    // ========== REGISTRO (público) ==========
    [HttpPost("registro")]
    public async Task<ActionResult<PersonaReadDTO>> Registro(RegistroDTO dto)
    {
        // 1. Normalizar el correo: "  Mateo@UPC.edu.co " -> "mateo@upc.edu.co"
        var correo = dto.correo.Trim().ToLowerInvariant();

        // 2. ¿Ya existe ese correo? -> 409 Conflict
        if (await _context.Personas.AnyAsync(p => p.correo == correo))
            return Conflict(new { mensaje = "El correo ya está registrado." });

        // 3. Crear la persona con la contraseña LICUADA
        var persona = new Persona
        {
            nombre = dto.nombre,
            apellido = dto.apellido,
            edad = dto.edad,
            correo = correo,
            password = BCrypt.Net.BCrypt.HashPassword(dto.password) // se guarda el HASH
        };

        _context.Personas.Add(persona);
        await _context.SaveChangesAsync();

        // 4. Responder SIN la contraseña (por eso se usa PersonaReadDTO)
        return Ok(new PersonaReadDTO
        {
            idPersona = persona.idPersona,
            nombre = persona.nombre,
            apellido = persona.apellido,
            edad = persona.edad,
            correo = persona.correo
        });
    }

    // ========== LOGIN (público) ==========
    [HttpPost("login")]
    public async Task<ActionResult<LoginRespuestaDTO>> Login(LoginDTO dto)
    {
        // 1. Buscar a la persona por su correo
        var correo = dto.correo.Trim().ToLowerInvariant();
        var persona = await _context.Personas.FirstOrDefaultAsync(p => p.correo == correo);

        // 2. Si no existe O la contraseña no coincide -> 401 con mensaje GENÉRICO
        if (persona is null || !VerificarPassword(dto.password, persona.password))
            return Unauthorized(new { mensaje = "Credenciales inválidas." });

        // 3. Todo bien -> fabricar la manilla
        var (token, expira) = _jwt.GenerarToken(persona);

        return Ok(new LoginRespuestaDTO
        {
            token = token,
            expira = expira,
            idPersona = persona.idPersona,
            nombre = $"{persona.nombre} {persona.apellido}"
        });
    }

    // ========== YO (requiere token) ==========
    [HttpGet("yo")]
    [Authorize] // solo este método pide token
    public IActionResult Yo()
    {
        // "User" lo llenó el portero (UseAuthentication) al leer tu token
        return Ok(new
        {
            idPersona = User.FindFirst("sub")?.Value,
            correo = User.FindFirst("email")?.Value,
            nombre = User.Identity?.Name
        });
    }

    // Compara la contraseña escrita con el hash guardado
    private static bool VerificarPassword(string password, string hashGuardado)
    {
        try
        {
            return BCrypt.Net.BCrypt.Verify(password, hashGuardado);
        }
        catch (BCrypt.Net.SaltParseException)
        {
            // La fila tiene una contraseña vieja en texto plano: no es un hash válido
            return false;
        }
    }
}
