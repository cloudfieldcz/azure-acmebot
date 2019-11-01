namespace KeyVault.Acmebot.Models
{
    public class AddCertificateRequest
    {
        public string[] Domains { get; set; }
        public string FrontDoor { get; set; }
    }
}