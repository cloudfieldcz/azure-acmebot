using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using KeyVault.Acmebot.Contracts;
using KeyVault.Acmebot.Models;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;

namespace KeyVault.Acmebot
{
    public class GetFrontDoorsFunctions
    {
        [FunctionName(nameof(GetFrontDoors))]
        public async Task<IList<AzureFrontDoor>> GetFrontDoors([OrchestrationTrigger] DurableOrchestrationContext context)
        {
            var activity = context.CreateActivityProxy<ISharedFunctions>();

            var frontdoors = await activity.GetAllFDoors();

            frontdoors.Insert(0, new AzureFrontDoor("#NO-FD-2048#", new List<string>()));
            frontdoors.Insert(0, new AzureFrontDoor("#NO-FD-4096#", new List<string>()));
            frontdoors.Insert(0, new AzureFrontDoor("#NO-FD-EXP-2048#", new List<string>()));
            frontdoors.Insert(0, new AzureFrontDoor("#NO-FD-EXP-4096#", new List<string>()));

            return frontdoors.ToArray();
        }

        [FunctionName(nameof(GetFrontDoors_HttpStart))]
        public async Task<HttpResponseMessage> GetFrontDoors_HttpStart(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "get-frontdoors")] HttpRequestMessage req,
            [OrchestrationClient] DurableOrchestrationClient starter,
            ILogger log)
        {
            if (!req.Headers.Contains("X-MS-CLIENT-PRINCIPAL-ID"))
            {
                return req.CreateErrorResponse(HttpStatusCode.Unauthorized, $"Need to activate EasyAuth.");
            }

            // Function input comes from the request content.
            string instanceId = await starter.StartNewAsync(nameof(GetFrontDoors), null);

            log.LogInformation($"Started orchestration with ID = '{instanceId}'.");

            return await starter.WaitForCompletionOrCreateCheckStatusResponseAsync(req, instanceId, TimeSpan.FromMinutes(2));
        }
    }
}