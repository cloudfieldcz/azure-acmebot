using System;
using System.Collections.Generic;
using System.Text;

namespace KeyVault.Acmebot.Models
{
    public class AzureFrontDoor
    {
        public AzureFrontDoor(string name, List<string> hostnames)
        {
            Name = name;
            Hostnames = hostnames;
        }
        public string Name { get; set; }
        public List<string> Hostnames { get; set; }
    }
}
