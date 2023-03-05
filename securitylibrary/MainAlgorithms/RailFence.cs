using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static System.Net.Mime.MediaTypeNames;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            int Key = 1;
            string Check_String = "";
            string Check_String_for_x = "";
            while (true)
            {
                Check_String = Encrypt(plainText, Key);

                Check_String_for_x = Check_String.Replace("\0", "X");
                Check_String = Check_String.Replace("\0", string.Empty);

                if (Check_String.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase)
                    || Check_String_for_x.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                {
                    break;
                }
                Key++;
            }
            return Key;    
        }

        public string Decrypt(string cipherText, int key)
        {
            // Declarations
            int Len = (int)Math.Ceiling((double)cipherText.Length / key);
            char[,] Char_Arr = new char[key, Len];
            string Result = "";
            int Row = 0;
            int Col = 0;

            // Fill the matrix row wise based
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (Col == Len)
                {
                    Col = 0;
                    Row++;
                }
                Char_Arr[Row, Col] = cipherText[i];
                Col++;
            }

            // reset values to reuse variables
            Row = 0;
            Col = 0;

            // Generate the plain text column wise 
            for (int i = 0; i < cipherText.Length; i++)
            {
                if (Row == key)
                {
                    Row = 0;
                    Col++;
                }
                Result += Char_Arr[Row, Col];
                Row++;
            }
            return Result;
        }

        public string Encrypt(string plainText, int key)
        {
            // Declarations
            int Len = (int)Math.Ceiling((double)plainText.Length / key);
            char[,] Char_Arr = new char[key, Len];
            string Result = "";
            int Row = 0;
            int Col = 0;

            // Fill the matrix column wise based on the key
            for (int i = 0; i < plainText.Length; i++)
            {
                if (Row == key)
                {
                    Row = 0;
                    Col++;
                }
                Char_Arr[Row, Col] = plainText[i];
                Row++;
            }

            // Generate the cipher text row wise
            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < Len; j++)
                {
                    Result += Char_Arr[i, j];
                }
            }
            return Result;
        }
    }
}
