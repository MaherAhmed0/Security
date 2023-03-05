using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        char[] alphabet = new char[] { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };
        string text = "";
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            string notFound = "";
            int notFoundIndex = 0;
            for(int i = 0; i < alphabet.Length; i++)
            {
                if (!cipherText.Contains(alphabet[i]))
                {
                    notFound += alphabet[i];
                }
            }
            for(int i = 0; i < alphabet.Length; i++)
            {
                bool isFound = false;
                int index = -1;
                for(int j = 0; j < plainText.Length; j++)
                {
                    if (plainText[j] == alphabet[i])
                    {
                        isFound = true;
                        index = j;
                    }
                }
                if (isFound)
                {
                    text += cipherText[index];
                }
                else
                {
                    text += notFound[notFoundIndex];
                    notFoundIndex++;
                }
            }
            return text;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (cipherText[i] == key[j])
                    {
                        text += alphabet[j];
                    }
                }
            }
            return text;
        }

        public string Encrypt(string plainText, string key)
        {
            for(int i = 0; i < plainText.Length; i++)
            {
                for (int j = 0; j < alphabet.Length; j++)
                {
                    if (plainText[i] == alphabet[j])
                    {
                        text += key[j];
                    }
                }
            }
            return text;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string frequency = "zqjxkvbywgpfmucdlhrsnioate";
            int[] array = new int[26];
            int count;
            for(int i = 0; i < alphabet.Length; i++)
            {
                count = 0;
                for(int j = 0; j < cipher.Length; j++)
                {
                    if (cipher[j] == alphabet[i])
                    {
                        count++;
                    }
                }
                array[i] = count;
            }
            for(int i = 0; i < array.Length; i++)
            {
                for(int j = 0; j < array.Length - 1; j++)
                {
                    if (array[j] > array[j + 1])
                    {
                        int temp = array[j + 1];
                        array[j + 1] = array[j];
                        array[j] = temp;
                        char t = alphabet[j + 1];
                        alphabet[j + 1] = alphabet[j];
                        alphabet[j] = t;
                    }
                }
            }
            string key = "";
            for(int i = 0; i < alphabet.Length; i++)
            {
                key += alphabet[i];
            }
            for (int i = 0; i < cipher.Length; i++)
            {
                int index = key.IndexOf(cipher[i]);
                text += frequency[index];
            }
            return text;
        }
    }
}