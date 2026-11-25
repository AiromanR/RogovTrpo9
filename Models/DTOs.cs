namespace RogovTRPO8.Models
{
    public partial class DTOs
    {
        public record TaskDTO(string title, string description);
        public record TaskDTOIsCompleted(string title, string description, bool isCompleted);
        public record AuthRequest(string Login, string Password); //9
        public record RefreshRequest(string refresh_token); //9
    }
}
