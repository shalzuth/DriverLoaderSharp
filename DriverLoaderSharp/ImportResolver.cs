using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace DriverLoaderSharp
{
    public class ImportResolver
    {
        public static Int32 SizeOfImage(Byte[] Image)
        {
            var headerOffset = BitConverter.ToInt32(Image, 0x3c);
            var optionalHeaderOffset = headerOffset + 0x18;
            return BitConverter.ToInt32(Image, optionalHeaderOffset + 0x38);
        }
        public static Byte[] ResolveKernelImports(Byte[] Image)
        {
            var headerOffset = BitConverter.ToInt32(Image, 0x3c);
            var optionalHeaderOffset = headerOffset + 0x18;
            var numberOfRva = BitConverter.ToInt32(Image, optionalHeaderOffset + 0x6c);
            if (numberOfRva <= 1) return Image;
            var importTableVa = BitConverter.ToInt32(Image, optionalHeaderOffset + 0x78);
            if (importTableVa == 0) return Image;
            var originalThunkPtr = BitConverter.ToInt32(Image, importTableVa + 0);
            var baseThunkPtr = BitConverter.ToInt32(Image, importTableVa + 16);
            for (int i = 0; ; i++)
            {
                var originalThunk2 = BitConverter.ToInt64(Image, originalThunkPtr + i * 8);
                if (originalThunk2 == 0) break;
                var thunk = BitConverter.ToInt64(Image, baseThunkPtr + i * 8);
                if (originalThunk2 > 0)
                {
                    var name = Encoding.Default.GetString(Image.Skip((int)originalThunk2 + 2).TakeWhile(b => b != 0).ToArray());
                    Array.Copy(BitConverter.GetBytes((UInt64)Natives.FindKernelProcedure(name)), 0, Image, baseThunkPtr + i * 8, 8);
                }
                else
                    throw new Exception("Fix this");
            }
            return Image;
        }
    }
}
