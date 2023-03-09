using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        // we will create array of capitallletters include 16 alphabet 
     char[] Capitalalphabet = new char[] { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z' };
    //then we will create function return index
     
       

       

        public string Decrypt(string cipherText, string key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToUpper();// we will make Ciophertext and Key Upper 

            key = key.ToUpper();

            StringBuilder strtostore= new StringBuilder(cipherText);// we will store ciphertext
            int strtostorelength = strtostore.Length;
            for (int i = 0; i < strtostorelength; i++)
            {
                if (strtostore[i] == 'J')//replace any J with I
                {
                    strtostore[i] = 'I';
                }
            }
            //string store have a cipher text

            for (int i = 0; ((i < strtostorelength) && ((i + 1) < strtostorelength)); i += 2)/// we will take two two letters
            {
                if (strtostore[i] == strtostore[i + 1])// if two lettters are the same we will replace second with x 
                    strtostore.Insert(i + 1, 'X');
            }

            if (strtostore.Length % 2 == 1)// if it odd number we wiLL ADD X
                strtostore.Append('X');

            
            char[,] Newmatrix = new char[5, 5];

            Newmatrix = definekey(key);//TEST_Case=RMCMBPIM

            int letter1_row = 0, letter1_col = 0, letter2_row = 0, letter2_col = 0;// FOr indices r2m el row 
            for (int i = 0; i < strtostore.Length; i += 2)
            {
                get_index_ofchar(Newmatrix, strtostore[i], ref letter1_row, ref letter1_col);
                get_index_ofchar(Newmatrix, strtostore[i + 1], ref letter2_row, ref letter2_col);

               
                if (letter1_col == letter2_col)//
                {
                    strtostore[i] = Newmatrix[(letter1_row + 4) % 5, letter1_col];
                    strtostore[i + 1] = Newmatrix[(letter2_row + 4) % 5, letter2_col];
                }
                else if (letter1_row == letter2_row)//IF BOTH AT tHE SAME ROW ->FIRST Case nfs r2m el row 
                {
                    strtostore[i] = Newmatrix[letter1_row, (letter1_col + 4) % 5];//If both at the same column second case
                    strtostore[i + 1] = Newmatrix[letter2_row, (letter2_col + 4) % 5];
                }
                else
                {
                    strtostore[i] = Newmatrix[letter1_row, letter2_col];
                    strtostore[i + 1] = Newmatrix[letter2_row, letter1_col];
                }
            }

            for (int i = strtostorelength - 1; i >= 0; i--)
            {
                if (strtostore[i] == 'X')
                {
                    if (i > 0)
                    {
                        if (i == (strtostorelength - 1) && i % 2 != 0)
                        {
                            strtostore.Remove(i, 1);
                        }
                        else if (strtostore[i - 1] == strtostore[i + 1] && i % 2 != 0)
                        {
                            strtostore.Remove(i, 1);
                        }
                    }
                }
            }

            string ciphertext = strtostore.ToString();//FROM  bUILDER TO STRIGN

            return ciphertext.ToLower();//and we will make it lower letter 
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToUpper();// first we will make Plain text to upper
            key = key.ToUpper();


            StringBuilder storestr = new StringBuilder(plainText);

            int storestringlength=storestr.Length;
            for (int i = 0; i < storestr.Length; i++)
            {
                if (storestr[i] == 'J')
                {
                    storestr[i] = 'I';
                }
            }

            for (int i = 0; ((i < storestringlength) && ((i + 1) < storestringlength)); i += 2)
            {
                if (storestr[i] == storestr[i + 1])
                    storestr.Insert(i + 1, 'X');
            }

            if (storestr.Length % 2 == 1)
                storestr.Append('X');

            char[,] matrix = new char[5, 5];
            matrix = definekey(key);

            int letter1_row = 0, letter1_col = 0, letter2_row = 0, letter2_col = 0;
            for (int i = 0; i < storestr.Length; i += 2)
            {
                get_index_ofchar(matrix, storestr[i], ref letter1_row, ref letter1_col);
                get_index_ofchar(matrix, storestr[i + 1], ref letter2_row, ref letter2_col);
                 if (letter1_col == letter2_col)
                {
                    storestr[i] = matrix[(letter1_row + 1) % 5, letter1_col];
                    storestr[i + 1] = matrix[(letter2_row + 1) % 5, letter2_col];
                }
                else if (letter1_row == letter2_row)
                {
               
                    storestr[i] = matrix[letter1_row, (letter1_col + 1) % 5];
                    storestr[i + 1] = matrix[letter2_row, (letter2_col + 1) % 5];

                }
               
                else
                {
                    storestr[i] = matrix[letter1_row, letter2_col];
                    storestr[i + 1] = matrix[letter2_row, letter1_col];
                }
            }

            string ciphertext = storestr.ToString();
            return ciphertext.ToUpper();
        }

        void get_index_ofchar(char[,] arr, char str, ref int letterrow1, ref int lettercol1)
        {
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {

                    if (arr[i, j] == str)
                    {
                        letterrow1 = i;

                        lettercol1 = j;

                        break;
                    }
                }
            }
        }

        char[,] definekey(string key)//Function to generate Key
        {
            var cleverkey = key.ToCharArray().Distinct().ToArray();//To not repeat Key in array

            var s = new String(cleverkey);
            StringBuilder key1 = new StringBuilder(s);//{}
            int key1lenght = key1.Length;
            for (int co = 0; co < key1lenght; co++)
            {
                if (key1[co] == 'J')//replace any character contains Key j with I

                    key1[co] = 'I';
            }

            char[] key2 = key1.ToString().ToCharArray();//key2 will continue reninder alphabet
            StringBuilder reminderaplhabet = new StringBuilder();
            int Capitalalphabetlenght = Capitalalphabet.Length;
            for (int co = 0; co < Capitalalphabetlenght; co++)
            {
                if (Capitalalphabet[co] != 'J')//in case alphabet dont equal j
                {
                    if (!key2.Contains(Capitalalphabet[co]))
                    {
                        reminderaplhabet.Append(Capitalalphabet[co]);
                    }
                }
            }

            string k = new string(key2);

            string k2 = reminderaplhabet.ToString();
            string Keyitself = k + k2;

            char[,] finalmatrix = new char[5, 5];//Matrixfinall that contains Key
            int c = 0;
            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    finalmatrix[i, j] = Keyitself[c];
                    c++;
                }
            }
            return finalmatrix;
        }


    }
}
