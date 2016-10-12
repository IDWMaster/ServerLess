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
    class Session:IDisposable
    {
        AesCryptoServiceProvider crypto;
        ICryptoTransform encryptor;
        ICryptoTransform decryptor;
        Guid localID;

        UdpClient client;
        IPEndPoint currentAddress;

        public bool Authenticated;
        public byte[] challenge;


        /// <summary>
        /// Validates a challenge
        /// </summary>
        /// <param name="response">The response to the challenge</param>
        /// <returns>true if the response matches the challenge; false otherwise</returns>
        public bool validateChallenge(byte[] response)
        {
            for(int i = 0;i<response.Length;i++)
            {
                if(challenge[i] != response[i])
                {
                    return false;
                }
            }
            return true;
        }
        public Guid id;
        /// <summary>
        /// Creates and initializes a new Session object
        /// </summary>
        /// <param name="key">The AES Session key to use</param>
        /// <param name="client">The UDP client to use</param>
        /// <param name="currentAddress">The IP Endpoint to associate this session with</param>
        /// <param name="localID">Your local ID</param>
        /// <param name="remoteID">The remote ID</param>
        public Session(byte[] key, UdpClient client, IPEndPoint currentAddress, Guid localID, Guid remoteID)
        {
            this.id = remoteID;
            this.client = client;
            this.localID = localID;
            this.currentAddress = currentAddress;
            crypto = new AesCryptoServiceProvider();
            crypto.Key = key;
            crypto.Mode = CipherMode.ECB;
            crypto.Padding = PaddingMode.None;
            encryptor = crypto.CreateEncryptor();
            decryptor = crypto.CreateDecryptor();
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
            {
                challenge = new byte[16];
                rng.GetBytes(challenge);
            }

        }
        
        unsafe void xor(byte* src, byte* dest, int len)
        {
            
            for(int i = 0;i<len;i++)
            {
                dest[i] ^= src[i];
            }
        }

        public int remotePort;
        public int localPort;

        /// <summary>
        /// Transmits a RAW packet in encrypted format. No additional processing other than AES encryption is added. If this is a data packet, fuzzing should take place to protect against cryptoanalysis attacks.
        /// </summary>
        /// <param name="data">The data to transmit</param>
        public unsafe void Send(byte[] data)
        {
            int dataLen = data.Length % 16 == 0 ? data.Length : data.Length+(16 - (data.Length % 16));
            if(dataLen != data.Length)
            {
                byte[] old = data;
                data = new byte[dataLen];
                Buffer.BlockCopy(old, 0, data, 0, old.Length);
            }
            encryptor.TransformBlock(data, 0, 16, data, 0);
            fixed (byte* array = data)
            {
                for (int i = 16; i < dataLen; i += 16)
                {
                    xor(array + i - 16, array + i, 16);
                    encryptor.TransformBlock(data, i, 16, data, i);
                }
            }

            MemoryStream mstream = new MemoryStream();
            BinaryWriter mwriter = new BinaryWriter(mstream);
            mwriter.Write(remotePort);
            mwriter.Write(data);
            client.Send(mstream.ToArray(), (int)mstream.Length, currentAddress);

        }


        
        /// <summary>
        /// Receives, and decodes an encrypted packet
        /// </summary>
        /// <param name="data">The ciphertext to decode. If possible; this buffer will be modified in-place</param>
        /// <returns>The decrypted data (length may be invalid)</returns>
        public unsafe byte[] Receive(byte[] data)
        {
            if(data.Length % 16 != 0) {
                throw new ArgumentException("Length of input must be evenly divisible by 16");
            }

            fixed(byte* array = data)
            {
                
                for(int i = data.Length-16;i>0;i-=16)
                {
                    decryptor.TransformBlock(data, i, 16, data, i);
                    xor(array + i - 16, array + i, 16);                    
                }
                decryptor.TransformBlock(data, 0, 16, data, 0);
            }
            return data;
        }

        #region IDisposable Support
        private bool disposedValue = false; // To detect redundant calls

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    crypto?.Dispose();
                    encryptor?.Dispose();
                    decryptor?.Dispose();
                }

                // TODO: free unmanaged resources (unmanaged objects) and override a finalizer below.
                // TODO: set large fields to null.

                disposedValue = true;
            }
        }

        // TODO: override a finalizer only if Dispose(bool disposing) above has code to free unmanaged resources.
        // ~Session() {
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
