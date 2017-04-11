using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.IO;
using System.Reflection;
using System.Diagnostics;

namespace EncryptionTesting
{
    class Program
    {
        static void Main(string[] args)
        {
            RijndaelManaged key = null;
            var directory = Path.GetDirectoryName(Assembly.GetExecutingAssembly().FullName);
            if (directory == null) return;
            var filename = Path.Combine(directory, "test.xml");
            if (File.Exists(filename))
                File.Delete(filename);
                using (var writer = new XmlTextWriter(filename, Encoding.UTF8))
                {
                    writer.Formatting = Formatting.Indented;
                    writer.WriteStartDocument();
                    writer.WriteStartElement("root");
                    writer.WriteStartElement("creditcard");
                    writer.WriteElementString("number", "29834209");
                    writer.WriteElementString("expiry", "01/01/2020");

                    writer.WriteEndElement();
                    writer.WriteEndElement();
                }
           
            try
            {
                //Create a new Key
                key = new RijndaelManaged();

                //Load the XML Document
                XmlDocument xmlDoc = new XmlDocument();
                xmlDoc.PreserveWhitespace = true;
                xmlDoc.Load("test.xml");

                //Encrypt the CreditCard
                Encrypt(xmlDoc, "creditcard", key);

                Console.WriteLine("The file has been encrypted");

                Console.WriteLine(xmlDoc.InnerXml);

                Decrypt(xmlDoc, key);

                Console.WriteLine("The document has been decrypted");

                Console.WriteLine(xmlDoc.InnerXml);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                //Clear the key
                if (key != null)
                {
                    key.Clear();
                }
            }
        }

        public static void Encrypt(XmlDocument Doc, String ElementName, SymmetricAlgorithm Key)
        {
            //Check the arguments provided
            if (Doc == null)
            {
                throw new ArgumentNullException("Doc");
            }
            else if (ElementName == null)
            {
                throw new ArgumentNullException("ElementToEncrypt");
            }
            else if (Key == null)
            {
                throw new ArgumentNullException("Algorithm");
            }

            //Find the specified xmlElement object, encrypt it then create a new xmlElement object
            XmlElement elementToEncrypt = Doc.GetElementsByTagName(ElementName)[0] as XmlElement;

            //Throw an XmlException if the element isn't found
            if (elementToEncrypt == null)
            {
                throw new XmlException("The specified element could not be found");
            }

            EncryptedXml eXml = new EncryptedXml();

            byte[] encryptedElement = eXml.EncryptData(elementToEncrypt, Key, false);

            //Create an EncryptedData object and populate it with the desired encrypted information
            EncryptedData edElement = new EncryptedData();
            edElement.Type = EncryptedXml.XmlEncElementUrl;

            //The EncryptionMethod so that the receiver knows which algorithm to use for decryption

            string encryptionMethod = null;

            if (Key is TripleDES)
            {
                encryptionMethod = EncryptedXml.XmlEncTripleDESUrl;
            }
            else if (Key is DES)
            {
                encryptionMethod = EncryptedXml.XmlEncDESUrl;
            }
            if (Key is Rijndael)
            {
                switch (Key.KeySize)
                {
                    case 128:
                        encryptionMethod = EncryptedXml.XmlEncAES128Url;
                        break;
                    case 192:
                        encryptionMethod = EncryptedXml.XmlEncAES192Url;
                        break;
                    case 256:
                        encryptionMethod = EncryptedXml.XmlEncAES256Url;
                        break;
                }
            }
            else
            {
                //Throw an exception if the transform is not in the previous categories
                throw new CryptographicException("The specified algorithm is not supported for XML");
            }

            edElement.EncryptionMethod = new EncryptionMethod(encryptionMethod);

            //Add the encrypted element data to the original XMlDocument object with the EncryptedData element
            edElement.CipherData.CipherValue = encryptedElement;

            //Replace the element from the original XmlDocument object with the Encrypted Data element
            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
        }

        public static void Decrypt(XmlDocument Doc, SymmetricAlgorithm Alg)
        {
            //Check the arguments provided
            if (Doc == null)
            {
                throw new ArgumentNullException("Doc");
            }
            else if (Alg == null)
            {
                throw new ArgumentNullException("Alg");
            }

            //Find the EncryptedDataElement in the XmlDocument
            XmlElement encryptedElement = Doc.GetElementsByTagName("EncryptedData")[0] as XmlElement;

            //If the EncryptedData element was not found throw an exception
            if (encryptedElement == null)
            {
                throw new XmlException("The EncryptedData element was not found.");
            }

            //Create an EncryptData object and populate it
            EncryptedData edElement = new EncryptedData();
            edElement.LoadXml(encryptedElement);

            //Create a new EncryptedXml object
            EncryptedXml exml = new EncryptedXml();

            //Decrypt the element using the symmetric key
            byte[] rgbOutput = exml.DecryptData(edElement, Alg);

            //Replace the encrytpedData element with the plaintext XML element
            exml.ReplaceData(encryptedElement, rgbOutput);
        }
    }
}
