using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
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

            key = FindSubSequence(key, plainText);
            // Breaking the key in substrings to find the original one
            Console.WriteLine(key);

            return key;
        }
  
        public string FindSubSequence(string key,string plainText)
        {
            for (int i = 2; i < key.Length; i++)  // looping on the index of the start of the plain text
            {
                for (int j = 3; j < key.Length; j++) // Looping on the length of the plain text in the key
                {
                    string temp = key.Substring(i, j);
                    if (plainText.Contains(temp))
                    {
                        return key.Substring(0, i);                       
                    }
                    else
                    {
                        break;
                    }
                }
            }

            return key;
        }
        
        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            int text_index = -1;  //indicator to the index of last char added to plainText
            int key_index = -1; //indicator to the index of last char added to key

            while (true)
            {


                // Applying decryption using the following formula Di = (Ei - Ki + 26) mod 26 
                for (int i = text_index + 1; i < key.Length; i++)
                {
                    int index = (alphabet.IndexOf(cipherText[i]) - alphabet.IndexOf(key[i]) + 26) % 26;
                    plainText += alphabet[index];
                    text_index = i; // saving index of last char in plain text
                }

                // Stopping condition of the while loop
                if (cipherText.Length == key.Length)  
                {
                    break;
                }
                
                // Making the key same length as the text from the plain text                              
                    for (int i =key_index + 1 ; i < plainText.Length; i++)
                    {
                        if (key.Length == cipherText.Length) break;
                        key += plainText[i];
                        key_index = i;  // saving index of last char in key
                    }  
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
                    key += plainText[i];
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
