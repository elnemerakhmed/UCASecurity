using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using UCASecurity.Encryption.Base;

namespace UCASecurity.Encryption.Algorithms
{
    public class RailFence : Algorithm<string, int, string>
    {
        public static char[][] BuildCleanMatrix(int rows, int cols)
        {
            char[][] result = new char[rows][];

            for (int row = 0; row < result.Length; row++)
            {
                result[row] = new char[cols];
            }

            return result;
        }
        private static string BuildStringFromMatrix(char[][] matrix)
        {
            string result = string.Empty;

            for (int row = 0; row < matrix.Length; row++)
            {
                for (int col = 0; col < matrix[row].Length; col++)
                {
                    if (matrix[row][col] != '\0')
                    {
                        result += matrix[row][col];
                    }
                }
            }

            return result;
        }
        private static char[][] Transpose(char[][] matrix)
        {
            char[][] result =
                BuildCleanMatrix(matrix[0].Length, matrix.Length);

            for (int row = 0; row < matrix.Length; row++)
            {
                for (int col = 0; col < matrix[row].Length; col++)
                {
                    result[col][row] = matrix[row][col];
                }
            }

            return result;
        }
        public override Result<string> Encrypt(string text, int key)
        {
            try
            {

                string output = string.Empty;

                char[][] matrix = BuildCleanMatrix(key, text.Length);

                int rowIncrement = 1;
                for (int row = 0, col = 0; col < matrix[row].Length; col++)
                {
                    if (
                        row + rowIncrement == matrix.Length ||
                        row + rowIncrement == -1
                        )
                    {
                        rowIncrement *= -1;
                    }

                    matrix[row][col] = text[col];

                    row += rowIncrement;
                }

                output = BuildStringFromMatrix(matrix);

                return new Result<string> { status = StatusCode.OK, payload = output };
            }
            catch (Exception)
            {
                return new Result<string> { status = StatusCode.Error, payload = string.Empty };
            }
        }
        public override Result<string> Decrypt(string cipher, int key)
        {
            try
            {
                string output = string.Empty;

                char[][] matrix = BuildCleanMatrix(key, cipher.Length);

                int rowIncrement = 1;
                int textIdx = 0;

                for (
                    int selectedRow = 0;
                    selectedRow < matrix.Length;
                    selectedRow++
                    )
                {
                    for (
                        int row = 0, col = 0;
                        col < matrix[row].Length;
                        col++
                        )
                    {
                        if (
                            row + rowIncrement == matrix.Length ||
                            row + rowIncrement == -1
                            )
                        {
                            rowIncrement *= -1;
                        }

                        if (row == selectedRow)
                        {
                            matrix[row][col] = cipher[textIdx++];
                        }

                        row += rowIncrement;
                    }
                }

                matrix = Transpose(matrix);
                output = BuildStringFromMatrix(matrix);

                return new Result<string> { status = StatusCode.OK, payload = output };
            }
            catch (Exception)
            {
                return new Result<string> { status = StatusCode.Error, payload = string.Empty };
            }
        }
        public override bool Health()
        {
            try
            {
                int key = 3;
                var cipherResult = Encrypt(Constants.Input, key);
                if (cipherResult.status == StatusCode.Error)
                {
                    throw new Exception();
                }

                var textResult = Decrypt(cipherResult.payload, key);
                if (textResult.status == StatusCode.Error)
                {
                    throw new Exception();
                }
                return textResult.payload.Equals(Constants.Input);
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
