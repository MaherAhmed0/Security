using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {
        char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        string text = "";
        public string Encrypt(string plainText, int key)
        {
            for (int i = 0; i < plainText.Length; i++)
            {
                for(int  j = 0; j < alphabet.Length; j++)
                {
                    if (alphabet[j] == plainText[i])
                    {
                        text += alphabet[(j + key) % 26];
                    }
                }
            }
            return text;
        }

        public string Decrypt(string cipherText, int key)
        {
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (alphabet[j] == cipherText[i])
                    {
                        int k = j;
                        if (j < key)
                        {
                            k =  j + 26;                           
                        }
                        text += alphabet[k - key];
                    }
                }
            }
            return text;
        }

        public int Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            int p = 0, c = 0;
            for (int i = 0; i < alphabet.Length; i++)
            {
                if(plainText[0] == alphabet[i])
                {
                    p = i;
                }
                if (cipherText[0] == alphabet[i])
                {
                    c = i;
                }
            }
            int key = c - p;
            if(key < 0)
            {
                key += 26;
            }
            return key;
        }
    }
}