using log4net;
using System;
using System.Configuration;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Threading;

namespace TcpListenerWindowsService
{
    public partial class TcpListenerService : ServiceBase
    {
        private static ILog _log;

        private readonly int _portNumber;
        private readonly string _localIPAddress;
        private readonly string _thumbprint;

        private readonly ManualResetEvent _stopRequested = new ManualResetEvent(false);

        private Thread _listenerThread;

        private X509Certificate2 serverCertificate = null;

        private bool IsStopRequested
        {
            get { return WaitHandle.WaitAll(new WaitHandle[] { _stopRequested }, 0, false); }
        }

        public ILog Log
        {
            get { return _log ?? (_log = LogManager.GetLogger(typeof(TcpListenerService))); }
        }

        public TcpListenerService()
        {
            InitializeComponent();

            _localIPAddress = ConfigurationManager.AppSettings["listeningIPAddress"];
            _portNumber = Convert.ToInt32(ConfigurationManager.AppSettings["listeningPort"]);
            _thumbprint = ConfigurationManager.AppSettings["thumbprint"];
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                _listenerThread = new Thread(StartListening);
                _listenerThread.Start();

                Log.Info(string.Format("{0} started listening on Address: {1}, Port: {2}", ServiceName, _localIPAddress, _portNumber));
            }
            catch (Exception ex)
            {
                Log.Error(ex);
                throw;
            }
        }

        protected override void OnStop()
        {
            try
            {
                _stopRequested.Set();

                Thread.Sleep(2000);
                try
                {
                    if (_listenerThread != null)
                        _listenerThread.Abort();
                }
                catch (ThreadAbortException)
                {
                }

                Log.Info(string.Format("{0} - listener service Address: {1}, Port: {2} has been stopped.",
                    ServiceName, _localIPAddress, _portNumber));
            }
            catch (Exception ex)
            {
                Log.Error(string.Format("{0} could not be stopped.", ServiceName), ex);
            }
        }

        public void StartListening()
        {
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);

            try
            {
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2Collection Results = store.Certificates.Find(X509FindType.FindByThumbprint, _thumbprint, false);

                if (Results.Count == 0)
                    throw new Exception("Unable to find certificate!");
                else
                    serverCertificate = Results[0];
            }
            catch (Exception ex)
            {
                throw ex;
            }
            finally
            {
                store.Close();
            }

            IPAddress localAddress = IPAddress.Parse(_localIPAddress);
            TcpListener tcpListener = new TcpListener(localAddress, _portNumber);

            tcpListener.Start();

            while (!IsStopRequested)
            {
                Log.Debug(string.Format("{0} is waiting for a connection ...", ServiceName));

                TcpClient tcpClient = tcpListener.AcceptTcpClient();
                if (tcpClient != null)
                {
                    Log.Info(string.Format("{0} accepted connection ...", ServiceName));

                    try
                    {
                        ProcessClient(tcpClient);
                    }
                    catch (Exception ex)
                    {
                        Log.Error(string.Format("{0} - error handling request.", ServiceName), ex);
                    }
                }
                else
                    break;
            }

            tcpListener.Stop();
        }


        public void ProcessClient(TcpClient client)
        {
            SslStream sslStream = new SslStream(
                client.GetStream(), false);
            try
            {
                sslStream.AuthenticateAsServer(serverCertificate, false, SslProtocols.Tls, true);
                DisplaySecurityLevel(sslStream);
                DisplaySecurityServices(sslStream);
                DisplayCertificateInformation(sslStream);
                DisplayStreamProperties(sslStream);

                sslStream.ReadTimeout = 5000;
                sslStream.WriteTimeout = 5000;
                Log.InfoFormat("Waiting for client message...");
                string messageData = ReadMessage(sslStream);
                Log.InfoFormat("Received: {0}", messageData);

                byte[] message = Encoding.UTF8.GetBytes("Hello from the server.<EOF>");
                sslStream.Write(message);
            }
            catch (AuthenticationException e)
            {
                Log.Error(string.Format("Exception: {0}", e.Message), e);
                Log.InfoFormat("Authentication failed - closing the connection.");
            }
            finally
            {
                sslStream.Close();
                client.Close();
            }
        }

        public string ReadMessage(SslStream sslStream)
        {


            byte[] buffer = new byte[2048];
            StringBuilder messageData = new StringBuilder();
            int bytes = -1;
            do
            {
                bytes = sslStream.Read(buffer, 0, buffer.Length);

                Decoder decoder = Encoding.UTF8.GetDecoder();
                char[] chars = new char[decoder.GetCharCount(buffer, 0, bytes)];
                decoder.GetChars(buffer, 0, bytes, chars, 0);
                messageData.Append(chars);
                if (messageData.ToString().IndexOf("<EOF>") != -1)
                    break;

            } while (bytes != 0);

            return messageData.ToString();
        }

        public void DisplaySecurityLevel(SslStream stream)
        {
            Log.InfoFormat("Cipher: {0} strength {1}. Hash: {2} strength {3}. Key exchange: {4} strength {5}. Protocol: {6}",
                stream.CipherAlgorithm, stream.CipherStrength,
                stream.HashAlgorithm, stream.HashStrength,
                stream.KeyExchangeAlgorithm, stream.KeyExchangeStrength,
                stream.SslProtocol);
        }
        public void DisplaySecurityServices(SslStream stream)
        {
            Log.InfoFormat("Is authenticated: {0} as server? {1}. IsSigned: {2}. Is Encrypted: {3}",
                stream.IsAuthenticated, stream.IsServer, stream.IsSigned, stream.IsEncrypted);
        }
        public void DisplayStreamProperties(SslStream stream)
        {
            Log.InfoFormat("Can read: {0}, write {1}. Can timeout: {2}",
                stream.CanRead, stream.CanWrite, stream.CanTimeout);
        }

        public void DisplayCertificateInformation(SslStream stream)
        {
            Log.InfoFormat("Certificate revocation list checked: {0}", stream.CheckCertRevocationStatus);

            X509Certificate localCertificate = stream.LocalCertificate;
            if (stream.LocalCertificate != null)
            {
                Log.InfoFormat("Local cert was issued to {0} and is valid from {1} until {2}.",
                    localCertificate.Subject,
                    localCertificate.GetEffectiveDateString(),
                    localCertificate.GetExpirationDateString());
            }
            else
                Log.InfoFormat("Local certificate is null.");

            X509Certificate remoteCertificate = stream.RemoteCertificate;
            if (stream.RemoteCertificate != null)
            {
                Log.InfoFormat("Remote cert was issued to {0} and is valid from {1} until {2}.",
                    remoteCertificate.Subject,
                    remoteCertificate.GetEffectiveDateString(),
                    remoteCertificate.GetExpirationDateString());
            }
            else
                Log.InfoFormat("Remote certificate is null.");

        }
    }
}
