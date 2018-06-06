using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;

namespace multiClient
{
    public partial class Form1 : Form
    {
        byte[] bufferKey,bufferIV;
        Socket sck;
        EndPoint epLocal, epRemote;
        public Form1()
        {
            InitializeComponent();
            sck = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
            sck.SetSocketOption(SocketOptionLevel.Socket,SocketOptionName.ReuseAddress,true);

            textLocalIp.Text = GetLocalIp();
            textFriendsIp.Text = GetLocalIp();
        }
        private string GetLocalIp()
        {
            IPHostEntry host;
            host = Dns.GetHostEntry(Dns.GetHostName());

            foreach (IPAddress ip in host.AddressList)
            {
                if (ip.AddressFamily == AddressFamily.InterNetwork)
                {
                    return ip.ToString();
                }
            }
            return "127.0.0.1";
        }
        private void MessageCallBack(IAsyncResult aResult)
        {
            try
            {
                int size = sck.EndReceiveFrom(aResult, ref epRemote);
                if (size > 0)
                {
                    //MessageBox.Show("size: " + size.ToString());
                    using (TripleDESCryptoServiceProvider myTripleDES = new TripleDESCryptoServiceProvider())
                    {

                        //Encrypt the string to an array of bytes.
                        byte[] receivedData = (byte[])aResult.AsyncState;

                        
                        Message m = (Message)BinaryDeserialize(receivedData);
                        
                        // Decrypt the bytes to a string.
                        string roundtrip = DecryptStringFromBytes(m.msg, m.Key, m.IV);


                        ASCIIEncoding encoding = new ASCIIEncoding();
                        //string receivedMessage = encoding.GetString(receivedData);
                        listMessage.Items.Add("Friend: " + roundtrip);
                    }
                    

                }
                byte[] buffer = new byte[500];
                sck.BeginReceiveFrom(buffer, 0, buffer.Length, SocketFlags.None, ref epRemote, new AsyncCallback(MessageCallBack), buffer);
            }
            catch (Exception exp)
            {
                MessageBox.Show(exp.ToString());
            }
        }
       
        private void button1_Click(object sender, EventArgs e)
        {
            try
            {
                epLocal = new IPEndPoint(IPAddress.Parse(textLocalIp.Text), Convert.ToInt32(textLocalPort.Text));
                sck.Bind(epLocal);

                epRemote = new IPEndPoint(IPAddress.Parse(textFriendsIp.Text), Convert.ToInt32(textFriendsPort.Text));
                sck.Connect(epRemote);

                byte[] buffer = new byte[500];
                sck.BeginReceiveFrom(buffer, 0, buffer.Length, SocketFlags.None ,ref epRemote, new AsyncCallback(MessageCallBack), buffer);

                button1.Text = "Connected";
                button1.Enabled = false;
                button2.Enabled = true;
                textMessage.Focus();
            }
            catch(Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            button2.Enabled = false;
        }
       
        private void button2_Click(object sender, EventArgs e)
        {
            try
            {
                using (TripleDESCryptoServiceProvider myTripleDES = new TripleDESCryptoServiceProvider())
                {
                    //Encrypt the string to an array of bytes.
                    System.Text.ASCIIEncoding enc = new System.Text.ASCIIEncoding();
                    bufferKey = myTripleDES.Key;
                    bufferIV = myTripleDES.IV;
                    byte[] encrypted = EncryptStringToBytes(textMessage.Text, bufferKey, bufferIV);


                    ////byte[] buffer = status.Serialize(); //fills the buffer with data
                    ////byte[] msg = enc.GetBytes("<" + textMessage.Text + ">");
                    Message p = new Message();
                    p.msg = encrypted;
                    p.Key = bufferKey;
                    p.IV = bufferIV;
                    byte[] sending =BinarySerialize(p);
                    

                    sck.Send(sending);
                    listMessage.Items.Add("You: " + textMessage.Text);
                    textMessage.Clear();
                }
            }
            

            catch (Exception ex)
            {
                MessageBox.Show(ex.ToString());
            }
        }
        public static byte[] BinarySerialize(object graph)
        {
            using (var stream = new MemoryStream())
            {
                var formatter = new BinaryFormatter();

                formatter.Serialize(stream, graph);

                return stream.ToArray();
            }
        }

        public static object BinaryDeserialize(byte[] buffer)
        {
            using (var stream = new MemoryStream(buffer))
            {
                var formatter = new BinaryFormatter();

                return formatter.Deserialize(stream);
            }
        }
        //DES ALGORITHM METHODS
        static byte[] EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");
            byte[] encrypted;
            // Create an TripleDESCryptoServiceProvider object
            // with the specified key and IV.
            using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
            {
                tdsAlg.Key = Key;
                tdsAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform encryptor = tdsAlg.CreateEncryptor(tdsAlg.Key, tdsAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }


            // Return the encrypted bytes from the memory stream.
            return encrypted;

        }
        //DES ALGORITHM METHODS
        static string DecryptStringFromBytes(byte[] cipherText, byte[] Key, byte[] IV)
        {
            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("Key");

            // Declare the string used to hold
            // the decrypted text.
            string plaintext = null;

            // Create an TripleDESCryptoServiceProvider object
            // with the specified key and IV.
            using (TripleDESCryptoServiceProvider tdsAlg = new TripleDESCryptoServiceProvider())
            {
                tdsAlg.Key = Key;
                tdsAlg.IV = IV;

                // Create a decrytor to perform the stream transform.
                ICryptoTransform decryptor = tdsAlg.CreateDecryptor(tdsAlg.Key, tdsAlg.IV);

                // Create the streams used for decryption.

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {

                            // Read the decrypted bytes from the decrypting stream
                            // and place them in a string.
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }
            return plaintext;
        }
    }
    [Serializable]
    public class Message
    {

        public  byte[] msg { get; set; }
        public  byte[] Key { get; set; }
        public  byte[] IV { get; set; }
    }
    

}
