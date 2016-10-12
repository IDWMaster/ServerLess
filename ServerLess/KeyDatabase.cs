using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Data.SQLite;
using System.Data.SQLite.Linq;
using System.Security.Cryptography;
using System.IO;
namespace ServerLess
{
    public class EncryptionKey
    {
        public string Thumbprint { get; set; }
        public byte[] RawKey { get; set; }
        public bool isPrivate { get; set; }
        public EncryptionKey GenerateThumbprint()
        {
            using(SHA512CryptoServiceProvider shankredemption = new SHA512CryptoServiceProvider())
            {
                using (RSACryptoServiceProvider msp = new RSACryptoServiceProvider())
                {
                    msp.ImportCspBlob(RawKey);
                    Thumbprint = new Guid(new BinaryReader(new MemoryStream(shankredemption.ComputeHash(msp.ExportCspBlob(false)))).ReadBytes(16)).ToString();
                    return this;
                }
            }
        }
    }
    class KeyDatabase
    {
        SQLiteCommand listPrivateKeys;
        SQLiteCommand addKey;
        SQLiteCommand findKey;
        SQLiteConnection connection;
        static KeyDatabase instance = new KeyDatabase();
        public IEnumerable<EncryptionKey> EnumeratePrivateKeys()
        {
            using(var reader = listPrivateKeys.ExecuteReader())
            {
                while(reader.Read())
                {
                    yield return new EncryptionKey() { isPrivate = true, RawKey = reader[1] as byte[], Thumbprint = reader[0] as string };
                }
            }
        }
        public EncryptionKey FindKey(Guid id)
        {
            findKey.Parameters.AddWithValue(null, id.ToString());
            using(var reader = findKey.ExecuteReader())
            {
                while(reader.Read())
                {
                    return new EncryptionKey() { Thumbprint = reader[0] as string, RawKey = reader[1] as byte[], isPrivate = (int)reader[2] > 0 };
                }
            }
            return null;
        }
        private KeyDatabase()
        {
            connection = new SQLiteConnection("Data Source=keydb");
            
            connection.Open();
            using(SQLiteCommand cmd = new SQLiteCommand("CREATE TABLE IF NOT EXISTS Keys (Thumbprint VARCHAR(128) PRIMARY KEY, Key BLOB, isPrivate INT)",connection))
            {
                cmd.ExecuteNonQuery();
            }
            listPrivateKeys = new SQLiteCommand("SELECT * FROM Keys WHERE isPrivate = 1",connection);
            addKey = new SQLiteCommand("INSERT INTO Keys VALUES (?, ? , ?)",connection);
            findKey = new SQLiteCommand("SELECT * FROM Keys WHERE Thumbprint = ?",connection);
        }
        public void InsertKey(EncryptionKey key)
        {
            addKey.Parameters.AddWithValue(null, key.Thumbprint);
            addKey.Parameters.AddWithValue(null, key.RawKey);
            addKey.Parameters.AddWithValue(null, key.isPrivate);
            addKey.ExecuteNonQuery();
        }
        public static void RunQuery(Action<KeyDatabase> callback)
        {
            lock(instance)
            {
                callback(instance);
            }
        }
    }
}
