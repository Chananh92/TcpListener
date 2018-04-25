using System.ServiceProcess;

namespace TcpListenerWindowsService
{
    static class Program
    {
        /// <summary>
        /// The main entry point for the application.
        /// </summary>
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new TcpListenerService()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}
