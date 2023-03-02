using System;
using System.Collections.Generic;
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
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            int Len = (int)Math.Ceiling((double)cipherText.Length / key);
            char[,] Char_Arr = new char[key, Len];
            string Result = "";
            int Row = 0;
            int Col = 0;

            for(int i = 0; i < cipherText.Length; i++)
            {
                if (Col == Len)
                {
                    Col = 0;
                    Row++;
                }
                Char_Arr[Row, Col] = cipherText[i];
                Col++;
            }
            Row = 0;
            Col = 0;
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
            int Len = (int)Math.Ceiling((double)plainText.Length / key);
            char[,] Char_Arr = new char[key, Len];
            string Result = "";
            int Row = 0;
            int Col = 0;

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
