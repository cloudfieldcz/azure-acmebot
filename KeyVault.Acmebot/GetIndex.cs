using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace KeyVault.Acmebot
{
    public class GetIndex
    {

        [FunctionName(nameof(GetIndex_HttpStart))]
        public async Task<HttpResponseMessage> GetIndex_HttpStart(
                [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = "index")] HttpRequestMessage req,
                [OrchestrationClient] DurableOrchestrationClient starter,
                ILogger log)
        {
            if (!req.Headers.Contains("X-MS-CLIENT-PRINCIPAL-ID"))
            {
                return req.CreateErrorResponse(HttpStatusCode.Unauthorized, $"Need to activate EasyAuth.");
            }

            var executingAssembly = Assembly.GetExecutingAssembly();
            string ret;
            using (Stream stream = executingAssembly.GetManifestResourceStream(
                string.Format("{0}.StaticContent.index.html", executingAssembly.GetName().Name)))
            using (StreamReader reader = new StreamReader(stream))
            {
                ret = reader.ReadToEnd();
            }

            var response = new HttpResponseMessage(HttpStatusCode.OK);
            response.Content = new StringContent(ret);
            response.Content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("text/html");
            return response;
        }
    }
}
