using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            char x = cipherText[0] , y = cipherText[1];
            int index1 = 0 , index2 = 0;
            bool temp = true;
            //for find the column
            for(int n=0;n<plainText.Length;n++)
            {
                if(plainText[n] == x && temp == true && plainText[n] != plainText[n+1])
                {
                    index1 = n;
                    temp = false;
                    continue;
                }
                
                if(plainText[n] == y && temp == false)
                {
                    index2 = n;
                    break;
                }
            }
            //normal encryption after find row and columns
            decimal column = (index2 - index1) ;
            decimal row = Math.Ceiling((cipherText.Length / column));

            char[,] matrixArr = new char[(int)row, (int)column];
            int i = 0, j = 0;
            foreach (char c in plainText)
            {
                if (j != column)
                {
                    matrixArr[i, j] = c;
                }
                if (j == column)
                {
                    j = 0;
                    i++;
                    matrixArr[i, j] = c;

                    if (i == row)
                    {
                        break;
                    }
                }
                j++;
            }
            
            List<int> templist = new List<int>();
            List<char> tempCharCipher = new List<char>();
            List<char> tempcharcipherConfirm = new List<char>();
            List<string> tempStringCipher = new List<string>();
            int t = 0;
            int t1 = 1;
            int t2 = 0;
            bool ForColumnRepeated=true;
            bool forStrings = true;
            bool forWrogchoose = true;
            bool finalBreak = true;
            int rt = 0;
            IDictionary<int, int> ArrTemp= new Dictionary<int, int>();
            
            //splitting the cipher text 
            for (int r = 0; r < cipherText.Length; r++)
            {
                forStrings = true;
                for (int l = 0; l < column; l++)
                {
                    forWrogchoose=true;
                    if (cipherText[r] == matrixArr[t,l])
                    {
                        rt = r;
                        for(int m=0;m<row-1; m++)
                        {
                            
                            if (cipherText[rt+m] == matrixArr[m,l])
                            {
                                tempCharCipher.Add(matrixArr[m, l]);
                                if (m == row - 2)
                                    continue;
                                r++;
                            }
                            else
                            {
                                forWrogchoose = false;
                                r = rt;
                                break;

                            }
                           
                        }
                        if(forWrogchoose==false)
                        {
                            continue;
                        }
                        string CT = new string(tempCharCipher.ToArray());
                       
                        for (int aaaa=0;aaaa<tempStringCipher.Count;aaaa++)
                        {
                            if (tempStringCipher[aaaa]==CT)
                            {
                                r = r - ((int)row - 2);
                                forStrings = false;
                                break;
                                
                            }
                        }
                        if(forStrings==false)
                        {
                            tempCharCipher.Clear();
                            break;
                        }
                        tempStringCipher.Add(CT);
                        tempCharCipher.Clear();
                        
                        if(ForColumnRepeated == true)
                        {
                            ArrTemp.Add(l, t1);
                            t1++;
                            if(ArrTemp.Count == column)
                            {
                                finalBreak = false;
                            }
                        }
                    }
                }
                if(finalBreak==false)
                {
                    break;
                }


            }
            //get the value for each key in arrtemp
            for(int last=0;last<ArrTemp.Count;last++)
            {
                int lasttemp = ArrTemp[last];
                templist.Add(lasttemp);
            }
            return templist;
            
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            decimal column = key.Count;
            decimal row = Math.Ceiling((cipherText.Length / column));
            List<char> tempChar = new List<char>();
            
            char[,] matrixArr = new char[(int)row, (int)column];
            int aa = 1;
            int cipher = 0;
            int columnIndex =0;
            
            while(aa != column+1)
            {
                for (int i = 0; i < key.Count; i++)
                {
                    if (key[i] == aa)
                    {
                        columnIndex = i;
                        aa++;
                        break;
                        
                    }

                }
                for(int j=0; j<row; j++)
                {
                    matrixArr[j, columnIndex] = cipherText[cipher];
                    char x = matrixArr[j, columnIndex];
                    cipher++;
                    if(cipher == cipherText.Length)
                    {
                        break;
                    }
                }

            }






            for (int i=0; i<row;i++)
            {
                for(int j=0;j<column;j++)
                {
                    tempChar.Add(matrixArr[i, j]);
                }
            }

            string PlainText = new string(tempChar.ToArray());
            return PlainText;






            throw new NotImplementedException();
        }

        public string Encrypt(string plainText, List<int> key)
        {
            decimal column = key.Count;
            int tempForKey = 1;
            decimal temp = -1;
            int i=0, j = 0;
            List<char> tempChar = new List<char>();
            foreach (char c in plainText)
            {
                temp++;
            }
            //int row = (int)Math.Floor( (decimal)(temp/column));
            decimal row = Math.Ceiling((temp / column));
            char[,] matrixArr = new char[(int)row, (int)column];
            foreach (char c in plainText)
            {
                if (j != column)
                {
                    matrixArr[i, j] = c;
                }
               
                if (j==column)
                {
                    j = 0;
                    i++;
                    matrixArr[i, j] = c;

                    if (i==row)
                    {
                        break;
                    }
                }
                
                
                j++;
                

            }
            int aa = 1;
            int jj = 0;
            while(aa!=column+1)
            {
                if (key[jj] == aa)
                {
                    for (int z = 0; z < row; z++)
                    {
                        tempChar.Add(matrixArr[z, jj]);
                    }
                    aa++;
                    jj = 0;
                    continue;
                }
                jj++;

            }

            string CT = new string(tempChar.ToArray());
            return CT;

            //throw new NotImplementedException();
        }
    }
}
