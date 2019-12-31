using MQTTnet;
using MQTTnet.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Nulah.Roomba.Models;
using Nulah.Roomba.Models.Responses;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Nulah.Roomba {
    // Most of this code is roughly ported from GetRoombaPassword in https://github.com/koalazak/dorita980
    public class Roomba980 {

        private readonly string _poseRegex = @"({""theta"":[\d-]+,""point"":{[xy:\"",\d-]+}})";
        private readonly ILogger _logger;

        public Roomba980() : this(new ConsoleLogger(true))
        {
        }

        public Roomba980(ILogger logger) 
        {
            _logger = logger;
        }

        /// <summary>
        /// Returns the details of the Roomba at the specified IPAddress on the network.
        /// <para>
        /// This method will only succeed if the HOME button has been held down for several seconds until the Roomba beeps, and the wifi light flashes green.
        /// </para>
        /// </summary>
        /// <param name="RobotLocalIP"></param>
        /// <returns></returns>
        public RoombaDetails GetDetails(IPAddress RobotLocalIP) {
            var roombaDetails = GetRobotPublicInfo(RobotLocalIP);
            var roombaPassword = GetRoombaPassword(RobotLocalIP);
            return new RoombaDetails() {
                LocalIp = RobotLocalIP,
                Credentials = new RoombaCredentials
                {
                    Password = roombaPassword,
                    Username = roombaDetails.hostname.Split('-').Last(),
                },
                Details = roombaDetails
            };
        }

        public class RoombaReceivedMessageEvent : EventArgs {
            public MqttMessagePayload Message { get; set; }
        }

        public delegate void OnReceivedMessage(object sender, RoombaReceivedMessageEvent e);

        public event OnReceivedMessage OnMessage;

        /// <summary>
        /// Returns public information about the Roomba, including configuration settings.
        /// <para>
        /// This method can be called at any time, and does not require you to have the home button pressed to get a response.
        /// </para>
        /// </summary>
        /// <param name="RobotLocalIP"></param>
        public Details GetRobotPublicInfo(IPAddress RobotLocalIP) {
            using (var udpClient = new UdpClient())
            {
                var msg = Encoding.ASCII.GetBytes("irobotmcs");

                udpClient.Send(msg, msg.Length, new IPEndPoint(RobotLocalIP, 5678));

                var res = udpClient.ReceiveAsync().Result;
                var roombaDetails = ParseBytesToType<Details>(res.Buffer);
                return roombaDetails;
            }
        }

        /// <summary>
        /// Casts a byte[] to a given type, where it's known that the byte[] represents a json structure
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="byteArray"></param>
        /// <returns></returns>
        private T ParseBytesToType<T>(byte[] byteArray) {
            var resString = Encoding.Default.GetString(byteArray);
            var deserialized = JsonConvert.DeserializeObject<T>(resString);
            return deserialized;
        }

        private async Task<MqttMessagePayload> ParseMQTTMessageToPayload(byte[] byteArray, string topic) {
            var resString = Encoding.Default.GetString(byteArray);
            var res = Task.Run(() => {

                dynamic s = JsonConvert.DeserializeObject(resString);

                JObject nestedObject = s.state.reported;
                var nestedTopics = nestedObject.Children()
                    .Select(x => new {
                        Value = (JProperty)x,
                        Key = ( (JProperty)x ).Name,
                        Path = ( (JProperty)x ).Path,
                        ObjectNested = ( x.Children().Count() == 1 && x.First.Children().Count() > 0 ),
                        Type = Type.GetType($"Nulah.Roomba.Models.Responses.{( (JProperty)x ).Name}", false, true)
                    });

                var messageGroup = "[Grouped] " + string.Join(",", nestedTopics.Select(x => x.Key));

                var timestamp = DateTime.UtcNow;
                _logger.Debug(resString, messageGroup);

                if(_logger.IsDebugEnabled)
                    nestedTopics.Select(x => {

                        if(x.Key == "langs") {
                            var settings = new JsonSerializerSettings {
                                TypeNameHandling = TypeNameHandling.Objects
                            };
                            settings.Converters.Add(new LangsConverter());

                            return new {
                                Topic = x.Key,
                                Path = ( x.ObjectNested ) ? x.Value.First.ToString(Formatting.None) : x.Value.ToString(Formatting.None),
                                obj = JsonConvert.DeserializeObject($"{{{x.Value.ToString()}}}", typeof(Langs), settings)
                            };
                        }
                        return new {
                            Topic = x.Key,
                            Path = ( x.ObjectNested ) ? x.Value.First.ToString(Formatting.None) : x.Value.ToString(Formatting.None),
                            obj = ( x.ObjectNested )
                            ? JsonConvert.DeserializeObject(x.Value.First.ToString(Formatting.None), x.Type)
                            : JsonConvert.DeserializeObject(x.Value.Parent.ToString(Formatting.None), x.Type)
                        };
                    }).ToList().ForEach(ptfl =>  _logger.Debug(ptfl.Path, ptfl.Topic));

                // Add to MqttMessage and figure out a way to bundle all the messages with it
                var nestedPath = nestedObject.First.Path;
                IEnumerable<MqttMessage> ms;
                if(nestedPath == "state.reported.pose") {
                    ms = Regex.Matches(resString, _poseRegex)
                        .Cast<Match>()
                        .Select(x => new MqttMessage {
                            Topic = "state.reported.pose",
                            Type = typeof(Pose),
                            Raw = x.Value,
                            Payload = JsonConvert.DeserializeObject<Pose>($"{x.Value}"),
                            TimeStamp = timestamp
                        });
                } else {
                    ms = nestedTopics.Select(x => {

                        if(x.Key == "langs") {
                            var settings = new JsonSerializerSettings {
                                TypeNameHandling = TypeNameHandling.Objects
                            };
                            settings.Converters.Add(new LangsConverter());

                            return new MqttMessage {
                                Topic = $"state.reported.langs",
                                Raw = $"{{{x.Value.ToString()}}}",
                                Type = typeof(Langs),
                                Payload = JsonConvert.DeserializeObject($"{{{x.Value.ToString()}}}", typeof(Langs), settings),
                                TimeStamp = timestamp
                            };
                        }

                        return new MqttMessage {
                            Topic = $"state.reported.{x.Key}",
                            Type = x.Type,
                            Raw = ( x.ObjectNested ) ? x.Value.First.ToString(Formatting.None) : x.Value.ToString(Formatting.None),
                            Payload = ( x.ObjectNested )
                                ? JsonConvert.DeserializeObject(x.Value.First.ToString(Formatting.None), x.Type)
                                : JsonConvert.DeserializeObject(x.Value.Parent.ToString(Formatting.None), x.Type),
                            TimeStamp = timestamp
                        };
                    });
                }

                var mqttres = new MqttMessagePayload {
                    Messages = ms.ToArray()
                };
                return mqttres;
            });
            return await res;
        }

        // Ignore all cert errors
        public static bool ValidateServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors) {
            return true;
        }

        /// <summary>
        /// Returns the password used to connect to the Roomba
        /// <para>
        /// This method will only work correctly if you have triggered wifi mode by holding the HOME button for several seconds until the roomba beeps.
        /// </para>
        /// </summary>
        /// <param name="RobotLocalIP"></param>
        /// <returns></returns>
        public string GetRoombaPassword(IPAddress RobotLocalIP) {

            using (var tcpClient = new TcpClient(RobotLocalIP.ToString(), port: 8883))
            {
                _logger.Info("Connected to Roomba");
                // Create an SSL stream that will close the client's stream.
                using( var sslStream = new SslStream(tcpClient.GetStream(),false,new RemoteCertificateValidationCallback(ValidateServerCertificate),null))
                {
                    try 
                    {
                        sslStream.AuthenticateAsClient("localhost");
                    } catch(AuthenticationException e) {
                        _logger.Error($"Exception: {e.Message}", e);
                        if(e.InnerException != null) {
                            _logger.Error($"Inner exception: {e.InnerException.Message}", e.InnerException);
                        }
                        _logger.Info("Authentication failed - closing the connection.");
                        tcpClient.Close();
                    }

                    // Send message to Roomba to get password
                    // TODO: figure out where this message was discovered, assuming it wasn't from
                    // sniffing the traffic
                    // Dug from https://github.com/pschmitt/roombapy/blob/master/roomba/password.py
                    /*
                        # this is 0xf0 (mqtt reserved) 0x05(data length)
                        # 0xefcc3b2900 (data)
                        [0]	240	byte // mqtt           0xf0
                        [1]	5	byte // message length 0x05
                        [2]	239	byte // message        0xef
                        [3]	204	byte // message        0xcc
                        [4]	59	byte // message        0x3b
                        [5]	41	byte // message        0x29
                        [6]	0	byte // message        0x00 - Based on errors returned, this seems like its a response flag, where 0x00 is OK, and 0x03 is ERROR? not sure
                                                              but details might be found in documentation for mqtt
                     */
                    byte[] messsage = { 0xf0, 0x05, 0xef, 0xcc, 0x3b, 0x29, 0x00 };
                    sslStream.Write(messsage);
                    sslStream.Flush();
                    return ReadMessage(sslStream);
                }
            }
        }

        private string ReadMessage(SslStream sslStream) {

            var buffer = new byte[35];
            string resString = null;
            var bytes = -1;

            while(( bytes = sslStream.Read(buffer, 0, buffer.Length) ) > 0) {
                // First message from the vacuum the length of the password
                /*
                    [0]	240	byte // mqtt           0xf0
                    [1]	35	byte // message length 0x35
                    the message length includes the original 5 bytes we sent to it.
                 */
                if(bytes == 2) {
                    continue;
                } else if(bytes > 7) {

                    //https://github.com/pschmitt/roombapy/blob/master/roomba/password.py#L129
                    // mentions this in more detail, but I think I could simplify a lot of this.
                    // buffer could be 35, and just read all.

                    // Skip the first 5 bytes we sent previously (0xef, 0xcc, 0x3b, 0x29, 0x00)
                    // the remaining 30 bytes is our password
                    var finalBuffer = buffer.Skip(5).ToArray();
                    // The result is UTF-8
                    resString = Encoding.UTF8.GetString(finalBuffer);
                    break;
                } else {
                    // Here the response will be the first 4 bytes of the message we sent,
                    // followed by 0x03 to indicate an error? Not too sure on that
                    /*
                        [2]	239	byte // message        0xef
                        [3]	204	byte // message        0xcc
                        [4]	59	byte // message        0x3b
                        [5]	41	byte // message        0x29
                        [4]	3	byte // error byte?    0x03  - not sure how this maps yet
                     */
                    throw new Exception("Failed to retrieve password. Did you hold the home button until it beeped?");
                }
            }
            return resString;
        }

        private IMqttClient client;

        public async Task ConnectToRoombaViaMQTT(IPAddress ip, RoombaCredentials credentials) {
            var opts = new MqttClientOptions {
                ClientId = credentials.Username,
                ChannelOptions = new MqttClientTcpOptions {
                    Port = 8883,
                    TlsOptions = new MqttClientTlsOptions {
                        AllowUntrustedCertificates = true,
                        IgnoreCertificateChainErrors = true,
                        IgnoreCertificateRevocationErrors = true,
                        UseTls = true
                    },
                    Server = ip.ToString()
                },
                Credentials = new MqttClientCredentials {
                    Username = credentials.Username,
                    Password = credentials.Password
                },
                CleanSession = false,
                ProtocolVersion = MQTTnet.Serializer.MqttProtocolVersion.V311,
                CommunicationTimeout = TimeSpan.FromSeconds(30)
            };

            var factory = new MqttFactory();

            client = factory.CreateMqttClient();

            client.Connected += (s, e) =>
            {
                if (OnMessage == null)
                    return;
                OnMessage(this, new RoombaReceivedMessageEvent {
                    Message = new MqttMessagePayload {
                        Messages = new[]{
                            new MqttMessage {
                                Payload = "Connected",
                                Raw = "Connected",
                                Type = typeof(string),
                                Topic = "event.roomba.connected"
                            }
                        }
                    }
                });
                _logger.Info("Connected to Roomba");
            };

            client.Disconnected += async (s, e) => {
                _logger.Info("Disconnected. Reconnecting");
                await client.ConnectAsync(opts);
            };

            client.ApplicationMessageReceived += async (s, e) => {
                var resMessage = await ParseMQTTMessageToPayload(e.ApplicationMessage.Payload, e.ApplicationMessage.Topic);
                if (OnMessage == null)
                    return;
                if(resMessage != null) {
                    OnMessage(this, new RoombaReceivedMessageEvent {
                        Message = resMessage
                    });
                } else {
                    _logger.Info($"Received message with topic {e.ApplicationMessage.Topic}: {{topic was not handled}}");
                }
            };

            await client.ConnectAsync(opts);
        }

        public async Task SendCommand(string commandString) {
            var foo = DateTime.UtcNow;
            var unixTime = ( (DateTimeOffset)foo ).ToUnixTimeSeconds();
            var applicationMessage = new MqttApplicationMessageBuilder()
                       .WithTopic("cmd")
                       .WithPayload($@"{{""command"":""{commandString}"",""time"":{unixTime},""initiator"":""localApp""}}")
                        .Build();
            await client.PublishAsync(applicationMessage);
        }
    }
}
