namespace Infrastructure.EMailLibrary.Models
{
    public class EMailRequest
    {
        public string To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }
    }
}
