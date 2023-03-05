using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        String alphabet = "abcdefghijklmnopqrstuvwxyz";
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();

            // Applying analysis using the following formula Ki = (Ei - Di + 26) mod 26
            for (int i = 0; i < cipherText.Length; i++)
            {

                int index = (alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(plainText[i]) + 26) % 26;
                key += alphabet[index];
            }

            // Breaking the key in substrings to find the original one
            for (int j = 4; j < 13; j++)  // looping on length of the original key
            {
                string temp = key.Substring(0, j);
                if (String.Equals(temp, key.Substring(j, j)))
                {
                    key = temp;
                    break;
                }
            }

            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower(); 


            // Making the key same length as the text 
            if (cipherText.Length != key.Length)
            {
                int i = 0;
                while (cipherText.Length != key.Length)
                {
                    key += key[i];
                    i++;
                }
            }

            // Applying decryption using the following formula Di = (Ei - Ki + 26) mod 26
            for (int i = 0; i < cipherText.Length; i++)  
            {
                
                int index = (alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(key[i]) + 26) % 26;
                plainText += alphabet[index];
            }

            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";

            // Making the key same length as the text 
            if (plainText.Length != key.Length)
            {
                int i = 0;
                while (plainText.Length != key.Length)
                {
                    key += key[i];
                    i++;
                }
            }

            // Applying encryption using the following formula Ei = (Pi + Ki) mod 26
            for (int i = 0; i < plainText.Length; i++)
            {
                int index = (alphabet.IndexOf(plainText[i]) + alphabet.IndexOf(key[i])) % 26;
                cipherText += alphabet[index];
            }

            return cipherText;
        }
    }
}