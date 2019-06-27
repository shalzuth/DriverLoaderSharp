using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

namespace DriverLoaderSharp
{
    public static class ServiceManager
    {
        public static bool IsInstalled(string serviceName)
        {
            IntPtr scm = OpenSCManager(Natives.ScmAccessRights.Connect);
            try
            {
                IntPtr service = Natives.OpenService(scm, serviceName, Natives.ServiceAccessRights.QueryStatus);
                if (service == IntPtr.Zero) return false;
                Natives.CloseServiceHandle(service);
                return true;
            }
            finally
            {
                Natives.CloseServiceHandle(scm);
            }
        }
        public static void InstallAndStart(string serviceName, string displayName, string fileName, out IntPtr servicePtr)
        {
            IntPtr scm = OpenSCManager(Natives.ScmAccessRights.AllAccess);
            try
            {
                IntPtr service = Natives.OpenService(scm, serviceName, Natives.ServiceAccessRights.AllAccess);
                if (service == IntPtr.Zero) service = Natives.CreateService(scm, serviceName, displayName, Natives.ServiceAccessRights.AllAccess, Natives.ServiceRights.SERVICE_KERNEL_DRIVER, Natives.ServiceBootFlag.DemandStart, Natives.ServiceError.Normal, fileName, null, IntPtr.Zero, null, null, null);
                if (service == IntPtr.Zero) throw new Exception("Open/Create Service Failed.");
                try
                {
                    StartService(service);
                    servicePtr = service;
                }
                finally
                {
                    Natives.CloseServiceHandle(service);
                }
            }
            finally
            {
                Natives.CloseServiceHandle(scm);
            }
        }

        public static void Start(string serviceName)
        {
            IntPtr scm = OpenSCManager(Natives.ScmAccessRights.AllAccess);
            try
            {
                IntPtr service = Natives.OpenService(scm, serviceName, Natives.ServiceAccessRights.AllAccess);
                if (service == IntPtr.Zero) return;//throw new Exception("Starting Service : OpenService Failed.");
                try
                {
                    StartService(service);
                }
                finally
                {
                    Natives.CloseServiceHandle(service);
                }
            }
            finally
            {
                Natives.CloseServiceHandle(scm);
            }
        }
        public static void StopService(string serviceName, Int32 deviceHandle = 0, Boolean uninstall = false)
        {
            IntPtr scm = OpenSCManager(Natives.ScmAccessRights.AllAccess);
            try
            {
                IntPtr service = Natives.OpenService(scm, serviceName, Natives.ServiceAccessRights.AllAccess);
                if (service == IntPtr.Zero) return;// throw new Exception("Stopping Service : OpenService Failed.");
                try
                {
                    if (deviceHandle != 0)
                        Natives.CloseHandle(new IntPtr(deviceHandle));
                    StopService(service);
                    if (uninstall)
                        if (!Natives.DeleteService(service))
                            throw new Exception("Delete Failed : " + Marshal.GetLastWin32Error());
                }
                finally
                {
                    Natives.CloseServiceHandle(service);
                }
            }
            finally
            {
                Natives.CloseServiceHandle(scm);
            }
        }

        private static void StartService(IntPtr service)
        {
            Natives.SERVICE_STATUS status = new Natives.SERVICE_STATUS();
            Natives.StartService(service, 0, 0);
            var changedStatus = WaitForServiceStatus(service, Natives.ServiceState.StartPending, Natives.ServiceState.Running);
            if (!changedStatus)
                Console.WriteLine("Start failed");
        }

        private static void StopService(IntPtr service)
        {
            Natives.SERVICE_STATUS status = new Natives.SERVICE_STATUS();
            Natives.ControlService(service, Natives.ServiceControl.Stop, status);
            var changedStatus = WaitForServiceStatus(service, Natives.ServiceState.StopPending, Natives.ServiceState.Stopped);
            if (!changedStatus)
                Console.WriteLine("Stop failed");
        }

        public static Natives.ServiceState GetStatus(string serviceName)
        {
            IntPtr scm = OpenSCManager(Natives.ScmAccessRights.Connect);
            try
            {
                IntPtr service = Natives.OpenService(scm, serviceName, Natives.ServiceAccessRights.QueryStatus);
                if (service == IntPtr.Zero) return Natives.ServiceState.NotFound;
                try
                {
                    return GetServiceStatus(service);
                }
                finally
                {
                    Natives.CloseServiceHandle(service);
                }
            }
            finally
            {
                Natives.CloseServiceHandle(scm);
            }
        }

        private static Natives.ServiceState GetServiceStatus(IntPtr service)
        {
            Natives.SERVICE_STATUS status = new Natives.SERVICE_STATUS();
            if (Natives.QueryServiceStatus(service, status) == 0)
                throw new Exception("QueryServiceStatus Failed.");
            return status.dwCurrentState;
        }

        private static bool WaitForServiceStatus(IntPtr service, Natives.ServiceState waitStatus, Natives.ServiceState desiredStatus)
        {
            Natives.SERVICE_STATUS status = new Natives.SERVICE_STATUS();
            Natives.QueryServiceStatus(service, status);
            if (status.dwCurrentState == desiredStatus) return true;
            int dwStartTickCount = Environment.TickCount;
            int dwOldCheckPoint = status.dwCheckPoint;
            while (status.dwCurrentState == waitStatus)
            {
                int dwWaitTime = status.dwWaitHint / 10;
                if (dwWaitTime < 1000) dwWaitTime = 1000;
                else if (dwWaitTime > 10000) dwWaitTime = 10000;
                Thread.Sleep(dwWaitTime);
                if (Natives.QueryServiceStatus(service, status) == 0) break;
                if (status.dwCheckPoint > dwOldCheckPoint)
                {
                    dwStartTickCount = Environment.TickCount;
                    dwOldCheckPoint = status.dwCheckPoint;
                }
                else if (Environment.TickCount - dwStartTickCount > 10000) break;// status.dwWaitHint) break;
            }
            return (status.dwCurrentState == desiredStatus);
        }

        private static IntPtr OpenSCManager(Natives.ScmAccessRights rights)
        {
            IntPtr scm = Natives.OpenSCManagerW(null, null, rights);
            if (scm == IntPtr.Zero) throw new ApplicationException("OpenSCManagerW Failed.");
            return scm;
        }

        public unsafe static void Load(String driverDisplayName, String driverFileName, String driverDeviceName, out IntPtr deviceHandle, out IntPtr serviceHandle, Byte[] driverBytes)
        {
            if (!IsInstalled(driverDisplayName))
            {
                File.WriteAllBytes(driverFileName, driverBytes);
                InstallAndStart(driverDisplayName, driverDisplayName, driverFileName, out serviceHandle);
            }
            else if (GetStatus(driverDisplayName) == Natives.ServiceState.Stopped)
                Start(driverDisplayName);
            while (true)
            {
                deviceHandle = Natives.CreateFile(driverDeviceName, FileAccess.ReadWrite, FileShare.None, IntPtr.Zero, FileMode.Open, FileAttributes.Normal, IntPtr.Zero);
                if (deviceHandle == IntPtr.Zero)
                    Thread.Sleep(250);
                else
                    break;
               
            }
            serviceHandle = deviceHandle;
        }
    }
}