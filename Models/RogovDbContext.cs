using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;

namespace RogovTRPO8.Models;

public partial class RogovDbContext : DbContext
{
    public RogovDbContext()
    {
    }

    public RogovDbContext(DbContextOptions<RogovDbContext> options)
        : base(options)
    {
    }

    public virtual DbSet<RefreshToken> RefreshTokens { get; set; }

    public virtual DbSet<RevokedToken> RevokedTokens { get; set; }

    public virtual DbSet<Task> Tasks { get; set; }

    public virtual DbSet<User> Users { get; set; }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        => optionsBuilder.UseSqlServer("Server=localhost\\SQLEXPRESS;Database=RogovDb;Trusted_Connection=True;TrustServerCertificate=True;");

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<RefreshToken>(entity =>
        {
            entity.HasIndex(e => e.Id, "IX_RefreshTokens").IsUnique();

            entity.Property(e => e.TokenHash).HasMaxLength(100);

            entity.HasOne(d => d.User).WithMany(p => p.RefreshTokens)
                .HasForeignKey(d => d.UserId)
                .OnDelete(DeleteBehavior.ClientSetNull)
                .HasConstraintName("FK_RefreshTokens_Users");
        });

        modelBuilder.Entity<RevokedToken>(entity =>
        {
            entity.HasIndex(e => e.Id, "IX_RevokedTokens").IsUnique();

            entity.Property(e => e.Jti).HasMaxLength(100);
        });

        modelBuilder.Entity<Task>(entity =>
        {
            entity.Property(e => e.OwnerLogin).HasMaxLength(100);
            entity.Property(e => e.Title).HasMaxLength(100);
        });

        modelBuilder.Entity<User>(entity =>
        {
            entity.Property(e => e.Login).HasMaxLength(100);
            entity.Property(e => e.Role).HasMaxLength(100);
        });

        OnModelCreatingPartial(modelBuilder);
    }

    partial void OnModelCreatingPartial(ModelBuilder modelBuilder);
}
