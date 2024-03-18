using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;

namespace AngularAuthAPI.Context
{
    public class AppDbContext :DbContext
    {
        public AppDbContext(DbContextOptions <AppDbContext> options) :base(options) // this option will get value from program.cs
        {
            
        }
        public DbSet<User> Users { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder) // it will send the entity from web api to dabase table
        {

            base.OnModelCreating(modelBuilder);
            modelBuilder.Entity<User>().ToTable("users");
        }
    }
}
