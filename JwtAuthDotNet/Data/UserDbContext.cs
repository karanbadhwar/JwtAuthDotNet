using JwtAuthDotNet.Entities;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthDotNet.Data;

public class UserDbContext : DbContext
{
    public UserDbContext(DbContextOptions options) : base(options)
    {
    }


    public DbSet<User> Users { get; set; }
}
