using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
//using System.Web.Script.Serialization;

namespace WebSocketServerCore
{

    public class ClientThreadEntity
    {
        public ClientThread ClientThread { get; set; }
        public Thread SysThread { get; set; }

    }
    public class Request_WSAuthenticate
    {
        public string Token { get; set; }
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class ClientThread
    {
        private EventWaitHandle _eStop;
        private EventWaitHandle _eExitLocal;
        private EventWaitHandle _eDataAvailable;

        private TcpListener _server;
        private TcpClient _client;
        private System.Timers.Timer _timer;
        private int _currentThreadId;
        private int _idleTime;

        public ClientThread(EventWaitHandle eStop, ref TcpListener webSocketServer, TcpClient client)
        {
            _eStop = eStop;
            _server = webSocketServer;
            _client = client;

            _timer = new System.Timers.Timer(1000);
            _timer.Elapsed += OnTimedEvent;
            _timer.AutoReset = true;
            //_timer.Enabled = true;


            _eExitLocal = new EventWaitHandle(false, EventResetMode.AutoReset);
            _eDataAvailable = new EventWaitHandle(false, EventResetMode.AutoReset);

        }

        public void Init()
        {
            try
            {
                _currentThreadId = Thread.CurrentThread.ManagedThreadId;
                //_timer.Enabled = true;
                Debug.WriteLine(" Waiting for Event... ", Thread.CurrentThread.ManagedThreadId);
                NetworkStream stream = _client.GetStream();

                while (_client.Connected)
                {
                    byte[] bytes = new byte[_client.Available];
                    int count = stream.Read(bytes, 0, _client.Available);
                    Debug.WriteLine(" Stream Read... ", Thread.CurrentThread.ManagedThreadId, count);
                    if (_client.Connected == false || (_client.Available == 0 && count <= 0))
                        break;

                    string s = Encoding.UTF8.GetString(bytes);



                    if (Regex.IsMatch(s, "^GET", RegexOptions.IgnoreCase))
                    {
                        Debug.WriteLine("=====Handshaking from client=====\n", s);

                        // 1. Obtain the value of the "Sec-WebSocket-Key" request header without any leading or trailing whitespace
                        // 2. Concatenate it with "258EAFA5-E914-47DA-95CA-C5AB0DC85B11" (a special GUID specified by RFC 6455)
                        // 3. Compute SHA-1 and Base64 hash of the new value
                        // 4. Write the hash back as the value of "Sec-WebSocket-Accept" response header in an HTTP response
                        string swk = Regex.Match(s, "Sec-WebSocket-Key: (.*)").Groups[1].Value.Trim();
                        string swka = swk + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
                        byte[] swkaSha1 = System.Security.Cryptography.SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(swka));
                        string swkaSha1Base64 = Convert.ToBase64String(swkaSha1);

                        // HTTP/1.1 defines the sequence CR LF as the end-of-line marker
                        byte[] response = Encoding.UTF8.GetBytes(
                            "HTTP/1.1 101 Switching Protocols\r\n" +
                            "Connection: Upgrade\r\n" +
                            "Upgrade: websocket\r\n" +
                            "Sec-WebSocket-Accept: " + swkaSha1Base64 + "\r\n\r\n");

                        stream.Write(response, 0, response.Length);
                    }
                    else
                    {
                        if (bytes.Length == 0)
                            continue;

                        bool fin = (bytes[0] & 0b10000000) != 0,
                            mask = (bytes[1] & 0b10000000) != 0; // must be true, "All messages from the client to the server have this bit set"

                        int opcode = bytes[0] & 0b00001111, // expecting 1 - text message
                            msglen = bytes[1] - 128, // & 0111 1111
                            offset = 2;

                        if (msglen == 126)
                        {
                            // was ToUInt16(bytes, offset) but the result is incorrect
                            msglen = BitConverter.ToUInt16(new byte[] { bytes[3], bytes[2] }, 0);
                            offset = 4;
                        }
                        else if (msglen == 127)
                        {
                            Debug.WriteLine("TODO: msglen == 127, needs qword to store msglen");
                            // i don't really know the byte order, please edit this
                            // msglen = BitConverter.ToUInt64(new byte[] { bytes[5], bytes[4], bytes[3], bytes[2], bytes[9], bytes[8], bytes[7], bytes[6] }, 0);
                            // offset = 10;
                        }

                        if (msglen == 0)
                            Debug.WriteLine("msglen == 0");

                        else if (mask)
                        {
                            byte[] decoded = new byte[msglen];
                            byte[] masks = new byte[4] { bytes[offset], bytes[offset + 1], bytes[offset + 2], bytes[offset + 3] };
                            offset += 4;

                            for (int i = 0; i < msglen; ++i)
                                decoded[i] = (byte)(bytes[offset + i] ^ masks[i % 4]);

                            string text = Encoding.UTF8.GetString(decoded);
                            Debug.WriteLine("", text);

                            try
                            {
                                //var a = new JavaScriptSerializer().Deserialize<object>(text);
                                var a = JsonSerializer.Deserialize<Request_WSAuthenticate>(text);
                                Debug.WriteLine("Buffer ", text);
                            }
                            catch (Exception ex)
                            {
                                Debug.WriteLine("JavaScriptSerializerException\n", ex.Message);
                            }


                        }
                        else
                            Debug.WriteLine("mask bit not set");





                    }

                }
                _timer.Enabled = false;
                _client.Close();
                Debug.WriteLine(" Basta... ", Thread.CurrentThread.ManagedThreadId);
            }
            catch (Exception ex) {
                if (_client != null && _client.Connected == true )
                _client.Close();
                Debug.WriteLine("*Basta*... ", Thread.CurrentThread.ManagedThreadId);
            }

        }

        public void Close() {
            if (_client != null)
                _client.Close();
        }

        private void OnTimedEvent(Object source, ElapsedEventArgs e)
        {


            if (_client != null)
            {
                _idleTime = 0;
                Debug.WriteLine("ClinetStatus:", _currentThreadId, _client.Connected);
            }
            else
            {
                _idleTime++;
                Debug.WriteLine("Idle", _currentThreadId);
            }




            //Debug.WriteLine(" The Elapsed event was raised at {1:HH:mm:ss.fff}",
            //                  Thread.CurrentThread.ManagedThreadId, e.SignalTime);
        }


        ~ClientThread()
        {
            _timer.Enabled = false;
            _timer.Dispose();
        }
    }

    public class WebSocketServer
    {
        private EventWaitHandle _eStop;
        private List<ClientThreadEntity> _threads;
        private TcpListener _server;
        private bool _amOk;

        public WebSocketServer()
        {
            _threads = new List<ClientThreadEntity>();
            _eStop = new EventWaitHandle(false, EventResetMode.ManualReset);

        }

        public void Start(string serverIp = "127.0.0.1", int serverPort = 3108)
        {
            _server = new TcpListener(IPAddress.Parse(serverIp), serverPort);
            _server.Start();
            Debug.WriteLine("Server has started on , Waiting for a connection... {0},{1}", serverIp, serverPort);

            Task.Run( async () =>
            {
                _amOk = true;
                Debug.WriteLine(" Waiting on clients...OK {0}", Thread.CurrentThread.ManagedThreadId);
                // Let's shoot out threads
                // upon incomming connection request from client
                while (_amOk)
                {
                    TcpClient client = _server.AcceptTcpClient();
                    await OnAcceptedClient(client);
                }
            });

            Debug.WriteLine(" Waiting on clients...Started {0}", Thread.CurrentThread.ManagedThreadId);

        }
        public void Stop()
        {
            _amOk = false;
            if (_eStop != null)
                _eStop.Set();

            foreach (var thrd in _threads) {
                if (thrd.SysThread.IsAlive)
                {
                    thrd.ClientThread.Close();
                    
                    //if (thrd.SysThread.IsAlive)
                    //    thrd.SysThread.Abort();

                    Debug.WriteLine(" Stoped {0}", Thread.CurrentThread.ManagedThreadId);
                }
            }
            _server.Stop();
            //Thread.CurrentThread.Abort();
        }


        private async Task OnAcceptedClient(TcpClient client)
        {
            Debug.WriteLine(" TcpClient Accepted...Start", Thread.CurrentThread.ManagedThreadId);
            ClientThread clientThread = new ClientThread(_eStop, ref _server, client);
            Thread thread = new Thread(new ThreadStart(clientThread.Init));
            _threads.Add(new ClientThreadEntity()
            {
                SysThread = thread,
                ClientThread = clientThread
            });
            
            thread.Start();
            

            // wait 0 seconds - or more if you need so 
            await Task.Delay(0);
        }
    }
}
