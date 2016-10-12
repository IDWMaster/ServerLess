using System;
using System.Linq;
using System.Security;
using System.Security.Cryptography;

/**
 * ServerLess is a secure, distributed, free, open-source, cross-platform networking suite.
 * ServerLess is intended to put you back in control of your content.
 * The ServerLess demon allows you to connect to an Internet ran by your peers. ServerLess is designed for use in both
 * secure and insecure environments. Our key design philsophies are as follows
 *  * Keep the community in control. Our software should be easily auditable, free of legal encumbrances, and widely accessible to the general public.
 *  * Keep the software secure. Ensure that every input to our software is sanitized before it enters a critical component. Ensure that we are using the latest, most secure cryptographic standards. Nothing should be sent in plaintext; ever, no matter how insignificant you think it is.
 *  * Build and maintain a strong developer community. Our community shall be open to everybody. Everyone deserves an equal say in the development of the Internet. To maintain this promise; a new decentralized development platform shall be developed on top of ServerLess. Our code should be as free as our technology.
 *  * Keep the core software as simple, and as portable as possible. Avoid the use of any non-standard tools or libraries as dependencies. Simplicity is the key to portability, maintainability, and security.
 * */
 


namespace ServerLess
{
    class Program
    {
        static Node client;
        static void Main(string[] args)
        {
            int defaultPort = 6881;
            KeyDatabase.RunQuery(db => {
                if(!db.EnumeratePrivateKeys().Any())
                {
                    Console.WriteLine("Generating encryption key....");
                    using(RSACryptoServiceProvider msp = new RSACryptoServiceProvider())
                    {
                        msp.KeySize = 8192;
                        byte[] generatedKey = msp.ExportCspBlob(true);
                        Console.WriteLine("Generated encryption key");
                        db.InsertKey(new EncryptionKey() { isPrivate = true, RawKey = generatedKey }.GenerateThumbprint());
                    }
                }
                var privkey = db.EnumeratePrivateKeys().First();
                Console.WriteLine("Your ID is " + privkey.Thumbprint);
                Node n = new Node(privkey, new System.Net.IPEndPoint(System.Net.IPAddress.IPv6Any, defaultPort));
                client = n;
                n.onPacketReceived += onPacketReceived;
                

            });

            while (true)
            {

                Console.WriteLine("Please enter a GUID to try pinging it; or enter an IPv6 address and port number (separated by space) to add a new route");
                string entry = Console.ReadLine();
                try
                {
                    client.Send(new byte[1], Guid.Parse(entry));
                }
                catch (Exception er)
                {
                    try
                    {
                        string[] ipPort = entry.Split(new char[] { ' ' },StringSplitOptions.RemoveEmptyEntries);
                        if(ipPort.Length == 2)
                        {
                            client.sendDiscover(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(ipPort[0]).MapToIPv6(), int.Parse(ipPort[1])));

                        }else
                        {
                            client.sendDiscover(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(ipPort[0]).MapToIPv6(), defaultPort));
                        }
                    }
                    catch(Exception err)
                    {
                        Console.WriteLine("The string entered was not recognized as a valid IP address or GUID.");
                    }
                }
            }
        }

        private static void onPacketReceived(byte[] packet, Guid from)
        {
            Console.WriteLine("Got message from " + from);
        }
    }
}
