using System;
using System.Net;
using System.Net.Sockets;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security;
using System.Security.Cryptography;
using System.IO;
namespace ServerLess
{
    /// <summary>
    /// A server/client implementation of the ServerLess protocol.
    /// </summary>
    class Node:IDisposable
    {

        /// <summary>
        /// Packet received delegate
        /// </summary>
        /// <param name="packet">The raw packet that was received</param>
        /// <param name="from">Who the packet came from (cryptographically verified)</param>
        public delegate void onReceiveDgate(byte[] packet, Guid from);
        public event onReceiveDgate onPacketReceived;

        

        HashSet<IPEndPoint> endpoints = new HashSet<IPEndPoint>();


        UdpClient mclient;

        List<Session> activeSessions = new List<Session>();

        Queue<int> availableIDs = new Queue<int>();
        Dictionary<Guid, Session> routingTable = new Dictionary<Guid, Session>();


        int allocateSession(Session session)
        {
            if(availableIDs.Any())
            {
                int slot = availableIDs.Dequeue();
                activeSessions[slot] = session;
                return slot;
            }
            activeSessions.Add(session);
            return activeSessions.Count;
        }

        void freeSession(int id)
        {
            try
            {
                routingTable.Remove(activeSessions[id].id);
                activeSessions[id].Dispose();
            }catch(Exception er)
            {
                Console.WriteLine(er+"\n\nThis usually indicates a bug in your program. Please report this to the friendly developers; your neighborhood goto velociraptor.");
            }
            activeSessions[id] = null;
            availableIDs.Enqueue(id);
        }
        bool running = true;
        EncryptionKey key;
        RSACryptoServiceProvider privateKey;
        byte[] pubkey;

        /// <summary>
        /// Constructs a new Node
        /// </summary>
        /// <param name="key">The encryption key to use</param>
        /// <param name="serverBinding">IP address and port number to bind the server to</param>
        public Node(EncryptionKey key, IPEndPoint serverBinding)
        {
            using(BinaryReader mreader = new BinaryReader(File.Open("peers",FileMode.OpenOrCreate)))
            {
                while(mreader.BaseStream.Position<mreader.BaseStream.Length)
                {
                    endpoints.Add(new IPEndPoint(new IPAddress(mreader.ReadInt64()), mreader.ReadInt32()));
                }
            }
            this.key = key;
            privateKey = new RSACryptoServiceProvider();
            privateKey.ImportCspBlob(key.RawKey);
            pubkey = privateKey.ExportCspBlob(false);
            mclient = new UdpClient(AddressFamily.InterNetworkV6);
            mclient.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, false);
            mclient.Client.Bind(serverBinding);
            startServer();
            Console.WriteLine("Server is active");
            managementThread();
        }
        public void sendDiscover(IPEndPoint ep)
        {
            Console.WriteLine("Sending discover request to " + ep);
            mclient.Send(new byte[] {0, 0, 0, 0, 1 },5,ep);
        }

        async void managementThread()
        {
            while(running)
            {
                if(activeSessions.Count == 0)
                {
                    Console.WriteLine("No active sessions. Discovering peers....");
                    foreach(var iable in endpoints)
                    {
                        sendDiscover(iable);
                    }
                }
                await Task.Delay(5000);
            }
        }

        byte[] decryptRSA(byte[] input)
        {
            return privateKey.Decrypt(input, true);
        }
        
        /// <summary>
        /// Sends a packet to the specified peer
        /// </summary>
        /// <param name="data">The packet to send</param>
        /// <param name="dest">The computer to send it to</param>
        public void Send(byte[] data, Guid dest)
        {
            if(routingTable.ContainsKey(dest))
            {
                //Send directly
                MemoryStream mstream = new MemoryStream();
                BinaryWriter mwriter = new BinaryWriter(mstream);
                mwriter.Write((byte)2);
                mwriter.Write(dest.ToByteArray());
                mwriter.Write(data);
                routingTable[dest].Send(mstream.ToArray());
            }else
            {
                Console.WriteLine("TODO: Packet routing");
            }
        }


        async void startServer()
        {
            while(running)
            {
                try
                {
                    var result = await mclient.ReceiveAsync();
                    endpoints.Add(result.RemoteEndPoint);
                    BinaryReader mreader = new BinaryReader(new MemoryStream(result.Buffer));
                    int sessionID = mreader.ReadInt32();
                    if (sessionID != 0)
                    {
                        //Possible active session (decode and process packet)
                        var session = activeSessions[sessionID];
                        mreader = new BinaryReader(new MemoryStream(session.Receive(mreader.ReadBytes((int)(mreader.BaseStream.Length - mreader.BaseStream.Position)))));
                        switch(mreader.ReadByte())
                        {
                            case 0:
                                {
                                    //Challenge request
                                    Console.WriteLine("Got challenge?");
                                    MemoryStream mstream = new MemoryStream();
                                    BinaryWriter mwriter = new BinaryWriter(mstream);
                                    mwriter.Write((byte)1);
                                    mwriter.Write(privateKey.Decrypt(mreader.ReadBytes(mreader.ReadUInt16()),true));
                                    session.Send(mstream.ToArray());

                                }
                                break;
                            case 1:
                                {
                                    if(session.Authenticated)
                                    {
                                        return;
                                    }
                                    Console.WriteLine("Got challenge response");
                                    if(session.validateChallenge(mreader.ReadBytes(16)))
                                    {
                                        Console.WriteLine("Challenge verified");
                                        session.Authenticated = true;
                                        routingTable.Add(session.id, session);
                                    }else
                                    {
                                        Console.WriteLine("Someone's been naughty.....");
                                        freeSession(session.localPort);
                                    }
                                }
                                break;
                            case 2:
                                {
                                    if (session.Authenticated)
                                    {
                                        //We've got data!
                                        Guid id = new Guid(mreader.ReadBytes(16));
                                        byte[] data = mreader.ReadBytes((int)(mreader.BaseStream.Length - mreader.BaseStream.Position));
                                        Console.WriteLine("Received " + data.Length + " bytes of data intended for " + id);
                                        if (id == new Guid(key.Thumbprint))
                                        {
                                            Console.WriteLine("Received packet destined for ourselves.");
                                            onPacketReceived?.Invoke(data, session.id);
                                        }
                                        else
                                        {
                                            Console.WriteLine("We need to route by XORing all routes to compute a distance vector");
                                        }
                                    }
                                }
                                break;
                        }

                    }
                    else
                    {
                        //No active session.
                        
                         switch(mreader.ReadByte())
                        {
                            case 0:
                                {

                                    //Session establishment request
                                    //Requesting ID
                                    mreader = new BinaryReader(new MemoryStream(decryptRSA(mreader.ReadBytes((int)(mreader.BaseStream.Length - mreader.BaseStream.Position)))));

                                    Guid id = new Guid(mreader.ReadBytes(16));
                                    Console.WriteLine("Received connection request from someone claiming to be " + id + ".");
                                    
                                    EncryptionKey foundKey = null;
                                    KeyDatabase.RunQuery(db => {
                                        foundKey = db.FindKey(id);
                                    });
                                    if(foundKey == null)
                                    {
                                        //No key available. Request it.
                                        Console.WriteLine("Requesting public key for " + id);
                                        MemoryStream mstream = new MemoryStream();
                                        BinaryWriter mwriter = new BinaryWriter(mstream);
                                        mwriter.Write(0);
                                        mwriter.Write((byte)1);
                                        mclient.Send(mstream.ToArray(), (int)mstream.Length,result.RemoteEndPoint);
                                    }else
                                    {
                                        //Send challenge to verify identity
                                        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
                                        {
                                            
                                            var session = new Session(mreader.ReadBytes(32), mclient, result.RemoteEndPoint,Guid.Parse(this.key.Thumbprint),new Guid(key.Thumbprint));
                                            sessionID = allocateSession(session);
                                            session.localPort = sessionID;
                                            session.remotePort = mreader.ReadInt32();
                                            MemoryStream mstream = new MemoryStream();
                                            BinaryWriter mwriter = new BinaryWriter(mstream);
                                            mwriter.Write((byte)0); //Challenge request
                                            using (RSACryptoServiceProvider msp = new RSACryptoServiceProvider())
                                            {
                                                msp.ImportCspBlob(foundKey.RawKey);
                                                byte[] encrypted = msp.Encrypt(session.challenge, true);
                                                mwriter.Write((ushort)encrypted.Length);
                                                mwriter.Write(encrypted);
                                            }
                                            session.Send(mstream.ToArray());
                                        }
                                    }
                                    
                                    break;
                                }
                            case 1:
                                {
                                    //Request public key
                                    MemoryStream mstream = new MemoryStream();
                                    BinaryWriter mwriter = new BinaryWriter(mstream);
                                    mwriter.Write(0);
                                    mwriter.Write((byte)2);
                                    mwriter.Write(pubkey);
                                    mclient.Send(mstream.ToArray(), (int)mstream.Length, result.RemoteEndPoint);

                                    break;
                                }
                            case 2:
                                {
                                    //Response to request for public key
                                    EncryptionKey key = new EncryptionKey();
                                    key.RawKey = mreader.ReadBytes((int)(mreader.BaseStream.Length - mreader.BaseStream.Position));
                                    key.isPrivate = false;
                                    key.GenerateThumbprint();
                                    Console.WriteLine("Received public key for " + key.Thumbprint);
                                    KeyDatabase.RunQuery(db => {
                                        if (db.FindKey(new Guid(key.Thumbprint)) == null)
                                        {
                                            db.InsertKey(key);
                                        }
                                    });
                                    Console.WriteLine("Connecting to " + key.Thumbprint + " through " + result.RemoteEndPoint);
                                    using (RNGCryptoServiceProvider msp = new RNGCryptoServiceProvider())
                                    {
                                        byte[] sessionKey = new byte[32];
                                        msp.GetBytes(sessionKey);
                                        Session session = new Session(sessionKey, mclient, result.RemoteEndPoint, new Guid(this.key.Thumbprint),new Guid(key.Thumbprint));
                                        session.Authenticated = true;
                                        session.localPort = allocateSession(session);
                                        MemoryStream mstream = new MemoryStream();
                                        BinaryWriter mwriter = new BinaryWriter(mstream);
                                        mwriter.Write(new Guid(this.key.Thumbprint).ToByteArray());
                                        mwriter.Write(sessionKey);
                                        mwriter.Write(session.localPort);
                                        MemoryStream cleartextStream = new MemoryStream();
                                        mwriter = new BinaryWriter(cleartextStream);
                                        mwriter.Write(0);
                                        mwriter.Write((byte)0);
                                        using (RSACryptoServiceProvider enc = new RSACryptoServiceProvider())
                                        {
                                            enc.ImportCspBlob(key.RawKey);
                                            mwriter.Write(enc.Encrypt(mstream.ToArray(),true));
                                        }
                                        byte[] content = cleartextStream.ToArray();
                                        mclient.Send(content, content.Length, result.RemoteEndPoint);
                                        
                                    }

                                }
                                break;
                        }          
                        
                    }
                }catch(Exception er)
                {
                    Console.WriteLine(er);

                }
            }
        }


        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    // TODO: dispose managed state (managed objects).
                    using (BinaryWriter mwriter = new BinaryWriter(File.Create("peers")))
                    {
                        foreach(var iable in endpoints)
                        {
                            mwriter.Write(iable.Address.GetAddressBytes());
                            mwriter.Write(iable.Port);
                        }
                    }
                    privateKey.Dispose();
                    mclient.Close();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~Node() {
        //   // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
        //   Dispose(false);
        // }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
            Dispose(true);
            // TODO: uncomment the following line if the finalizer is overridden above.
            // GC.SuppressFinalize(this);
        }
        #endregion

    }
}
