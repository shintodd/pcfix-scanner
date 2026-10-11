using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using System.IO;
using System.Management;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Shapes;
using System.Windows.Threading;
using Microsoft.Win32;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace PcfixScanner
{
    public class App : Application
    {
        [STAThread]
        public static void Main()
        {
            string baseDir = AppDomain.CurrentDomain.BaseDirectory;
            AppDomain.CurrentDomain.UnhandledException += (s, e) =>
            {
                try { File.WriteAllText(System.IO.Path.Combine(baseDir, "crash_domain.log"), e.ExceptionObject.ToString()); } catch { }
            };

            try
            {
                App app = new App();
                app.DispatcherUnhandledException += (s, e) =>
                {
                    try { File.WriteAllText(System.IO.Path.Combine(baseDir, "crash_dispatcher.log"), e.Exception.ToString()); } catch { }
                    e.Handled = true;
                };
                app.Run(new MainWindow());
            }
            catch (Exception ex)
            {
                try { File.WriteAllText(System.IO.Path.Combine(baseDir, "crash_main.log"), ex.ToString()); } catch { }
            }
        }
    }

    public class DiskItem
    {
        public int Index { get; set; }
        public string Model { get; set; }
        public string SerialNumber { get; set; }
        public string FirmwareRevision { get; set; }
        public double SizeGb { get; set; }
        public string InterfaceType { get; set; }
        public string Status { get; set; }
        public int BadBlockCount { get; set; }
        public bool IsBootloader { get; set; }
        public bool IsWindowsOs { get; set; }
        public List<string> Volumes { get; set; }

        // Real drive health, from MSFT_PhysicalDisk / MSFT_StorageReliabilityCounter (root\Microsoft\Windows\Storage).
        // Distinct from the coarse Win32_DiskDrive "Status" field above, which only ever says OK/Error and is NOT SMART.
        public string SmartHealthStatus { get; set; } // "Healthy" | "Warning" | "Unhealthy" | "Unknown" (Unknown = not queried / needs Administrator)
        public int? SmartWearPercent { get; set; }
        public int? SmartTemperatureCelsius { get; set; }
        public long? SmartPowerOnHours { get; set; }
        public long? SmartReadErrorsUncorrected { get; set; }

        public DiskItem()
        {
            Model = "Unknown Drive";
            SerialNumber = "";
            FirmwareRevision = "";
            InterfaceType = "Internal";
            Status = "OK";
            Volumes = new List<string>();
            SmartHealthStatus = "Unknown";
        }

        // Verified physical drive death (Tier 1): severe wear, SMART unhealthy, uncorrectable
        // errors, or a predictive-failure status flag. Bad block read retries are NOT death.
        public bool IsSsdDeath
        {
            get
            {
                if (SmartWearPercent.HasValue && SmartWearPercent.Value >= 95) return true;
                if (SmartHealthStatus == "Unhealthy") return true;
                if ((SmartReadErrorsUncorrected ?? 0) > 0) return true;
                if (Status != null &&
                    (Status.IndexOf("Pred Fail", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     Status.IndexOf("Error", StringComparison.OrdinalIgnoreCase) >= 0 ||
                     Status.IndexOf("Degraded", StringComparison.OrdinalIgnoreCase) >= 0)) return true;
                return false;
            }
        }

        public bool IsFailing
        {
            get { return IsSsdDeath; }
        }

        public bool HasReadRetries
        {
            get { return BadBlockCount > 0; }
        }

        public string GetHealthBadge()
        {
            if (IsSsdDeath)
            {
                if (SmartHealthStatus == "Unhealthy" || (SmartReadErrorsUncorrected ?? 0) > 0)
                {
                    return string.Format("CRITICAL FAILURE (SMART Unhealthy, {0} Uncorrected Errors)", SmartReadErrorsUncorrected ?? 0);
                }
                if (SmartWearPercent.HasValue && SmartWearPercent.Value >= 95)
                {
                    return string.Format("CRITICAL FAILURE ({0}% Wear)", SmartWearPercent.Value);
                }
                return string.Format("CRITICAL FAILURE ({0})", Status);
            }
            if (Status != "OK")
            {
                return string.Format("WARNING ({0})", Status);
            }
            if (SmartHealthStatus == "Warning")
            {
                return "WARNING (SMART Predictive Failure)";
            }
            if (BadBlockCount > 0)
            {
                return string.Format("DEGRADED ({0:N0} Read Retries)", BadBlockCount);
            }
            if (SmartHealthStatus == "Healthy")
            {
                return "HEALTHY (SMART Verified)";
            }
            return "HEALTHY (SMART Unavailable)";
        }
    }


    // =====================================================================
    // Upgrade 1: Direct Win32 IOCTL S.M.A.R.T. Engine
    // =====================================================================
    // Budget SATA SSDs (Apacer AS350, PUSKILL, generic ODM) often do NOT expose the
    // MSFT_StorageReliabilityCounter log page, so WMI returns Wear/Temp/Hours as N/A even
    // when elevated. Every SATA drive implements raw ATA SMART attributes, which we read
    // here with SMART_RCV_DRIVE_DATA (0x7C088) via DeviceIoControl.
    //
    // This is a read-only diagnostic path. It needs the same elevation as the WMI
    // reliability counter (physical-drive handle with write access), so on a standard-user
    // run it fails cleanly and the caller keeps its existing fallback. Never throws.
    public class SataSmartIoctlReader
    {
        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateFile(
            string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DeviceIoControl(
            IntPtr hDevice, uint dwIoControlCode,
            byte[] lpInBuffer, uint nInBufferSize,
            byte[] lpOutBuffer, uint nOutBufferSize,
            out uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        private const uint GENERIC_READ = 0x80000000;
        private const uint GENERIC_WRITE = 0x40000000;
        private const uint FILE_SHARE_READ = 0x00000001;
        private const uint FILE_SHARE_WRITE = 0x00000002;
        private const uint OPEN_EXISTING = 3;
        private const uint SMART_RCV_DRIVE_DATA = 0x0007C088;

        private static readonly IntPtr InvalidHandle = new IntPtr(-1);

        // Parsed subset of the 512-byte ATA SMART attribute table.
        public class SmartData
        {
            public bool HasWear;
            public int WearPercent;
            public bool HasTemp;
            public int TemperatureCelsius;
            public bool HasHours;
            public long PowerOnHours;
            public bool HasReallocated;
            public long ReallocatedSectors;
            public bool HasUncorrectable;
            public long UncorrectableErrors;
        }

        // Reads raw SMART for a physical drive index (0 = PhysicalDrive0). Returns an empty
        // SmartData on any failure; never throws.
        public static SmartData ReadPhysicalDrive(int driveIndex)
        {
            SmartData d = new SmartData();
            IntPtr h = IntPtr.Zero;
            try
            {
                string path = string.Format("\\\\.\\PhysicalDrive{0}", driveIndex);

                // Full access first (SMART read commands need write on the handle for most
                // SATA controllers); fall back to read-only which works on some AHCI stacks.
                h = CreateFile(path, GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                if (h == IntPtr.Zero || h == InvalidHandle)
                {
                    h = CreateFile(path, GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
                }
                if (h == IntPtr.Zero || h == InvalidHandle) return d;

                // SENDCMDINPARAMS: 32-byte fixed header + cBufferSize input bytes.
                //   [0..3]   cBufferSize
                //   [4..11]  IDEREGS (bFeaturesReg..bReserved)
                //   [12]     bDriveNumber
                //   [13..15] bReserved[3]
                //   [16..31] dwReserved[4]
                int cb = 512;
                byte[] inBuf = new byte[32 + cb];
                BitConverter.GetBytes(cb).CopyTo(inBuf, 0);
                inBuf[5] = 0x01;  // bSectorCountReg
                inBuf[6] = 0x01;  // bSectorNumberReg
                inBuf[7] = 0x4F;  // bCylLowReg   (SMART_CYL_LOW)
                inBuf[8] = 0xC2;  // bCylHighReg  (SMART_CYL_HI)
                inBuf[9] = 0xA0;  // bDriveHeadReg (SMART_DRIVE_HEAD)
                inBuf[10] = 0xB0; // bCommandReg  (SMART_READ_DATA)
                inBuf[12] = (byte)driveIndex;

                // SENDCMDOUTPARAMS: 16-byte header + 512-byte data.
                byte[] outBuf = new byte[16 + cb];
                uint returned = 0;
                if (!DeviceIoControl(h, SMART_RCV_DRIVE_DATA, inBuf, (uint)inBuf.Length,
                        outBuf, (uint)outBuf.Length, out returned, IntPtr.Zero))
                {
                    return d;
                }

                ParseAttributes(outBuf, 16, d);
            }
            catch
            {
                // Any marshalling or IO error: report nothing rather than crash the scan.
            }
            finally
            {
                if (h != IntPtr.Zero && h != InvalidHandle)
                {
                    try { CloseHandle(h); } catch { }
                }
            }
            return d;
        }

        // 30 attributes x 12 bytes, starting at byte 2 of the 512-byte data area.
        //   [0]      attribute id
        //   [1..2]   flags
        //   [3]      current (normalized) value
        //   [4]      worst value
        //   [5..10]  raw value (6 bytes, little-endian)
        //   [11]     reserved
        private static void ParseAttributes(byte[] buf, int baseOffset, SmartData d)
        {
            for (int i = 0; i < 30; i++)
            {
                int off = baseOffset + 2 + i * 12;
                if (off + 12 > buf.Length) break;
                int id = buf[off];
                if (id == 0) continue;

                int current = buf[off + 3];
                ulong raw = 0;
                for (int j = 5; j >= 0; j--)
                {
                    raw = (raw << 8) | buf[off + 5 + j];
                }

                switch (id)
                {
                    case 0x05: // Reallocated Sector Count
                        if (raw > 0) { d.ReallocatedSectors = (long)raw; d.HasReallocated = true; }
                        break;
                    case 0x09: // Power-On Hours Count
                        if (raw > 0) { d.PowerOnHours = (long)raw; d.HasHours = true; }
                        break;
                    case 0xBB: // Reported Uncorrectable Errors
                        if (raw > 0) { d.UncorrectableErrors = (long)raw; d.HasUncorrectable = true; }
                        break;
                    case 0xC2: // Temperature (Celsius). Some drives put it in the low byte, some
                               // in the full raw value, some in the normalized value.
                        if (!d.HasTemp)
                        {
                            int t = (int)(raw & 0xFF);
                            if (t < 1 || t > 150) t = (raw >= 1 && raw <= 150) ? (int)raw : 0;
                            if (t < 1 || t > 150) t = (current >= 1 && current <= 150) ? current : 0;
                            if (t >= 1 && t <= 150) { d.TemperatureCelsius = t; d.HasTemp = true; }
                        }
                        break;
                    case 0xCA: // Percentage Lifetime Used (raw = % endurance consumed)
                        if (raw <= 100) { d.WearPercent = (int)raw; d.HasWear = true; }
                        break;
                    case 0xE7: // SSD Life Left (normalized current = remaining %)
                    case 0xE9: // Media Wearout Indicator (normalized current = remaining %)
                        if (!d.HasWear && current >= 0 && current <= 100)
                        {
                            int wear = 100 - current;
                            if (wear < 0) wear = 0;
                            if (wear > 100) wear = 100;
                            d.WearPercent = wear;
                            d.HasWear = true;
                        }
                        break;
                }
            }
        }
    }

    // =====================================================================
    // Upgrade 2: GPU PCIe Link Width & Generation Validator
    // =====================================================================
    // A sagging card or a dirty slot pin can silently renegotiate an RTX-class GPU down to
    // x1/x4 or Gen1/Gen2 with zero driver errors, causing stutter. The PCI bus driver exposes
    // the negotiated state as device properties (DEVPKEY_PciDevice_CurrentLinkSpeed / Width),
    // which SetupAPI reads without Administrator rights. We compare current vs max and flag
    // a critical hardware alert when a discrete GPU is running below x8.
    public class PcieLinkSpeedDetector
    {
        [StructLayout(LayoutKind.Sequential)]
        private struct DevPropKey
        {
            public Guid Fmtid;
            public uint Pid;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SpDevInfoData
        {
            public int cbSize;
            public Guid ClassGuid;
            public uint DevInst;
            public IntPtr Reserved;
        }

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr SetupDiGetClassDevs(
            ref Guid classGuid, string enumerator, IntPtr hwndParent, uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiEnumDeviceInfo(
            IntPtr deviceInfoSet, uint memberIndex, ref SpDevInfoData deviceInfoData);

        [DllImport("setupapi.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiGetDeviceInstanceId(
            IntPtr deviceInfoSet, ref SpDevInfoData deviceInfoData,
            System.Text.StringBuilder deviceInstanceId, uint deviceInstanceIdSize, out uint requiredSize);

        [DllImport("setupapi.dll", SetLastError = true, EntryPoint = "SetupDiGetDevicePropertyW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiGetDeviceProperty(
            IntPtr deviceInfoSet, ref SpDevInfoData deviceInfoData, ref DevPropKey propertyKey,
            out uint propertyType, byte[] propertyBuffer, uint propertyBufferSize,
            out uint requiredSize, uint flags);

        [DllImport("setupapi.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

        private static readonly Guid DevClassDisplay = new Guid("4d36e968-e325-11ce-bfc1-08002be10318");
        private const uint DIGCF_PRESENT = 0x00000002;
        private const uint DEVPROP_TYPE_UINT32 = 0x00000007;

        private static readonly Guid PciPropSet = new Guid("3ab22e31-8264-4b4e-9af5-a8d2d8e33e62");
        private static DevPropKey KeyCurrentLinkSpeed;
        private static DevPropKey KeyCurrentLinkWidth;
        private static DevPropKey KeyMaxLinkSpeed;
        private static DevPropKey KeyMaxLinkWidth;

        public class GpuLinkState
        {
            public string InstanceId;
            public uint CurrentSpeed;   // 1=2.5, 2=5.0, 3=8.0, 4=16.0, 5=32.0 GT/s
            public uint CurrentWidth;   // lanes
            public uint MaxSpeed;
            public uint MaxWidth;
        }

        static PcieLinkSpeedDetector()
        {
            KeyCurrentLinkSpeed.Fmtid = PciPropSet; KeyCurrentLinkSpeed.Pid = 9;
            KeyCurrentLinkWidth.Fmtid = PciPropSet; KeyCurrentLinkWidth.Pid = 10;
            KeyMaxLinkSpeed.Fmtid = PciPropSet;     KeyMaxLinkSpeed.Pid = 11;
            KeyMaxLinkWidth.Fmtid = PciPropSet;     KeyMaxLinkWidth.Pid = 12;
        }

        // Enumerates PRESENT display-class devices and returns the PCIe link state for the
        // first discrete PCI GPU found (PNPDeviceID starts with PCI\VEN_). Returns null when
        // no discrete PCI GPU exists or every property read fails. Never throws.
        public static GpuLinkState DetectDiscreteGpu()
        {
            IntPtr devInfoSet = IntPtr.Zero;
            try
            {
                Guid cls = DevClassDisplay;
                devInfoSet = SetupDiGetClassDevs(ref cls, null, IntPtr.Zero, DIGCF_PRESENT);
                if (devInfoSet == IntPtr.Zero || devInfoSet == new IntPtr(-1)) return null;

                for (uint i = 0; ; i++)
                {
                    SpDevInfoData d = new SpDevInfoData();
                    d.cbSize = Marshal.SizeOf(typeof(SpDevInfoData));
                    if (!SetupDiEnumDeviceInfo(devInfoSet, i, ref d)) break;

                    string instId = GetInstanceId(devInfoSet, ref d);
                    if (string.IsNullOrEmpty(instId)) continue;
                    if (!instId.StartsWith("PCI\\VEN_", StringComparison.OrdinalIgnoreCase)) continue;
                    // Skip virtual/paravirtual display adapters (Parsec, VirtualBox, Hyper-V, RemoteFX).
                    if (instId.IndexOf("10DE", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        instId.IndexOf("1002", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        instId.IndexOf("8086", StringComparison.OrdinalIgnoreCase) >= 0)
                    {
                        GpuLinkState st = new GpuLinkState();
                        st.InstanceId = instId;
                        st.CurrentSpeed = ReadUint32(devInfoSet, ref d, ref KeyCurrentLinkSpeed);
                        st.CurrentWidth = ReadUint32(devInfoSet, ref d, ref KeyCurrentLinkWidth);
                        st.MaxSpeed = ReadUint32(devInfoSet, ref d, ref KeyMaxLinkSpeed);
                        st.MaxWidth = ReadUint32(devInfoSet, ref d, ref KeyMaxLinkWidth);
                        if (st.CurrentSpeed > 0 || st.CurrentWidth > 0) return st;
                    }
                }
            }
            catch { }
            finally
            {
                if (devInfoSet != IntPtr.Zero && devInfoSet != new IntPtr(-1))
                {
                    try { SetupDiDestroyDeviceInfoList(devInfoSet); } catch { }
                }
            }
            return null;
        }

        private static string GetInstanceId(IntPtr set, ref SpDevInfoData d)
        {
            uint required = 0;
            SetupDiGetDeviceInstanceId(set, ref d, null, 0, out required);
            if (required == 0) return null;
            System.Text.StringBuilder sb = new System.Text.StringBuilder((int)required + 1);
            if (!SetupDiGetDeviceInstanceId(set, ref d, sb, (uint)sb.Capacity, out required)) return null;
            return sb.ToString();
        }

        private static uint ReadUint32(IntPtr set, ref SpDevInfoData d, ref DevPropKey key)
        {
            byte[] buf = new byte[16];
            uint type = 0;
            uint required = 0;
            if (!SetupDiGetDeviceProperty(set, ref d, ref key, out type, buf, (uint)buf.Length, out required, 0)) return 0;
            if (type != DEVPROP_TYPE_UINT32 || required < 4) return 0;
            return BitConverter.ToUInt32(buf, 0);
        }

        // "x16 Gen4" / "x8 Gen3" / "x1 Gen1"
        public static string DescribeLink(uint width, uint speed)
        {
            string w = width > 0 ? string.Format("x{0}", width) : "x?";
            string g = speed > 0 ? string.Format("Gen{0}", speed) : "Gen?";
            return string.Format("{0} {1}", w, g);
        }

        public static string DescribeSpeed(uint speed)
        {
            switch (speed)
            {
                case 1: return "2.5 GT/s";
                case 2: return "5.0 GT/s";
                case 3: return "8.0 GT/s";
                case 4: return "16.0 GT/s";
                case 5: return "32.0 GT/s";
                default: return "unknown";
            }
        }
    }

    // =====================================================================
    // Upgrade 4: Deep Kernel-Power Event 41 Forensic Discriminator
    // =====================================================================
    // Event 41 records every unclean shutdown identically, but the EventData payload carries
    // three fields that separate a real power fault from a user action or a sleeping machine:
    //   BugcheckCode       >0  = a bluescreen happened before the power cut (decode separately)
    //   PowerButtonTimestamp >0  = the physical button was held ~4 s (manual hard reset)
    //   SleepInProgress    true = the machine was sleeping/suspending when power dropped
    // When all three are zero/false, the shutdown is unexplained by software: wall power cut,
    // failing PSU, or a loose 24-pin/ATX cable. This class parses those fields out of the XML.
    public class KernelPowerEventDecoder
    {
        public class Event41
        {
            public uint BugcheckCode;
            public ulong PowerButtonTimestamp;
            public bool SleepInProgress;
            public string Time;
        }

        // Parses the three discriminator fields from an Event 41 record's XML. Never throws;
        // missing fields read as their zero/false defaults.
        public static Event41 Parse(EventRecord rec)
        {
            Event41 e = new Event41();
            try
            {
                string xml = rec.ToXml();
                e.BugcheckCode = ReadUint(xml, "BugcheckCode");
                e.PowerButtonTimestamp = ReadUlong(xml, "PowerButtonTimestamp");
                e.SleepInProgress = ReadBool(xml, "SleepInProgress");
                if (rec.TimeCreated.HasValue) e.Time = rec.TimeCreated.Value.ToString("yyyy-MM-dd HH:mm:ss");
            }
            catch { }
            return e;
        }

        // Human verdict string for the report/log.
        public static string Verdict(Event41 e)
        {
            if (e == null) return "unknown";
            if (e.BugcheckCode != 0)
            {
                return string.Format("Bugcheck 0x{0:X} ({1}) before power cut", e.BugcheckCode, MainWindow.DecodeStopCode(e.BugcheckCode));
            }
            if (e.PowerButtonTimestamp != 0)
            {
                return "Manual hard reset (power button held 4+ seconds)";
            }
            if (e.SleepInProgress)
            {
                return "Power loss while sleeping or suspending (hibernation/sleep transition)";
            }
            return "Hardware Power Loss / PSU Transient Trip (wall power cut, failing power supply, or loose 24-pin cable)";
        }

        private static uint ReadUint(string xml, string name)
        {
            Match m = Regex.Match(xml, "<Data Name=['\"]" + Regex.Escape(name) + "['\"]>([^<]*)</Data>", RegexOptions.IgnoreCase);
            if (!m.Success) return 0;
            uint v;
            if (uint.TryParse(m.Groups[1].Value.Trim(), out v)) return v;
            return 0;
        }

        private static ulong ReadUlong(string xml, string name)
        {
            Match m = Regex.Match(xml, "<Data Name=['\"]" + Regex.Escape(name) + "['\"]>([^<]*)</Data>", RegexOptions.IgnoreCase);
            if (!m.Success) return 0;
            ulong v;
            if (ulong.TryParse(m.Groups[1].Value.Trim(), out v)) return v;
            return 0;
        }

        private static bool ReadBool(string xml, string name)
        {
            Match m = Regex.Match(xml, "<Data Name=['\"]" + Regex.Escape(name) + "['\"]>([^<]*)</Data>", RegexOptions.IgnoreCase);
            if (!m.Success) return false;
            string v = m.Groups[1].Value.Trim().ToLowerInvariant();
            return v == "1" || v == "true";
        }
    }

    // =====================================================================
    // Upgrade 3: Pure C# 5.0 Micro QR Code Engine (Mobile Emergency Bridge)
    // =====================================================================
    // Self-contained QR matrix generator. No external libraries. Byte-mode encoding only,
    // ECC level L, version auto-selected in [3..6]. Output is a bool[,] matrix where true =
    // dark module. The Render method turns the matrix into a WPF Grid of Rectangle pixels.
    //
    // QR reference (ISO/IEC 18004): the matrix is built from function patterns (finders,
    // separators, timing, alignment, format info, version info) plus the encoded codewords,
    // then masked with the mask pattern that minimises penalty score. This is a compact
    // implementation; it trades space for a little extra code and covers the payload sizes
    // the scanner hands off (a URL of a few hundred bytes).
    // =====================================================================
    // Upgrade 3: Pure C# 5.0 Micro QR Code Engine (Mobile Emergency Bridge)
    // =====================================================================
    // Self-contained QR matrix generator, no external libraries. Byte-mode only, ECC level L,
    // version auto-selected in [3..6]. Generate(text) returns a bool[,] matrix (true = dark).
    // Render(matrix, ...) draws it as a WPF Grid of Rectangle modules.
    public class MicroQrCodeRenderer
    {
        // ---- GF(2^8), primitive polynomial 0x11D ----
        private static readonly byte[] Exp = BuildExp();
        private static readonly byte[] Log = BuildLog(Exp);

        private static byte[] BuildExp()
        {
            byte[] e = new byte[512];
            int x = 1;
            for (int i = 0; i < 255; i++)
            {
                e[i] = (byte)x;
                x <<= 1;
                if ((x & 0x100) != 0) x ^= 0x11D;
            }
            for (int i = 255; i < 512; i++) e[i] = e[i - 255];
            return e;
        }

        private static byte[] BuildLog(byte[] exp)
        {
            byte[] l = new byte[256];
            for (int i = 0; i < 255; i++) l[exp[i]] = (byte)i;
            return l;
        }

        private static byte GfMul(byte a, byte b)
        {
            if (a == 0 || b == 0) return 0;
            return Exp[Log[a] + Log[b]];
        }

        // Reed-Solomon remainder. gen[0] is the highest-degree coefficient (x^ecCount).
        private static byte[] RsEncode(byte[] data, int ecCount)
        {
            byte[] gen = new byte[ecCount + 1];
            gen[0] = 1;
            for (int i = 0; i < ecCount; i++)
            {
                byte factor = Exp[i]; // alpha^i
                byte[] next = new byte[ecCount + 1];
                for (int j = 0; j < ecCount; j++)
                {
                    next[j] ^= gen[j];                     // x * gen[j]
                    next[j + 1] ^= GfMul(gen[j], factor);  // factor * gen[j]
                }
                Array.Copy(next, gen, ecCount + 1);
            }

            byte[] rem = new byte[data.Length + ecCount];
            Array.Copy(data, rem, data.Length);
            for (int i = 0; i < data.Length; i++)
            {
                byte c = rem[i];
                if (c != 0)
                {
                    for (int j = 0; j <= ecCount; j++)
                    {
                        rem[i + j] ^= GfMul(gen[j], c);
                    }
                }
            }
            byte[] ec = new byte[ecCount];
            Array.Copy(rem, data.Length, ec, 0, ecCount);
            return ec;
        }

        // ---- Version tables (ECC L): { totalCodewords, ecPerBlock, blocks } ----
        private static readonly int[,] VersionL =
        {
            {  70, 15, 1 }, // v3
            { 100, 20, 1 }, // v4
            { 134, 26, 1 }, // v5
            { 172, 18, 2 }, // v6
        };

        private static int SizeOf(int version) { return 17 + version * 4; }

        // Versions 2-6 have a single alignment pattern.
        private static int[] AlignmentCenters(int version)
        {
            return new int[] { 6, SizeOf(version) - 7 };
        }

        // ---- Entry point ----
        public static bool[,] Generate(string text)
        {
            if (text == null) text = "";
            int version = ChooseVersion(text);
            int size = SizeOf(version);
            bool[,] m = new bool[size, size];

            int total = VersionL[version - 3, 0];
            int ecPerBlock = VersionL[version - 3, 1];
            int blocks = VersionL[version - 3, 2];
            int dataPerBlock = (total - ecPerBlock * blocks) / blocks;

            byte[] data = BuildDataCodewords(text, total - ecPerBlock * blocks);

            byte[][] dataBlocks = new byte[blocks][];
            byte[][] ecBlocks = new byte[blocks][];
            for (int b = 0; b < blocks; b++)
            {
                dataBlocks[b] = new byte[dataPerBlock];
                Array.Copy(data, b * dataPerBlock, dataBlocks[b], 0, dataPerBlock);
                ecBlocks[b] = RsEncode(dataBlocks[b], ecPerBlock);
            }

            byte[] codewords = new byte[total];
            int cw = 0;
            for (int i = 0; i < dataPerBlock; i++)
                for (int b = 0; b < blocks; b++)
                    codewords[cw++] = dataBlocks[b][i];
            for (int i = 0; i < ecPerBlock; i++)
                for (int b = 0; b < blocks; b++)
                    codewords[cw++] = ecBlocks[b][i];

            PlaceFunctionPatterns(m, version);
            byte[] bits = CodewordsToBits(codewords, total, version);
            PlaceData(m, bits, version);

            bool[,] best = null;
            int bestPenalty = int.MaxValue;
            for (int mask = 0; mask < 8; mask++)
            {
                bool[,] candidate = ApplyMask(m, mask, version);
                PlaceFormatInfo(candidate, mask, version);
                int p = Penalty(candidate);
                if (p < bestPenalty)
                {
                    bestPenalty = p;
                    best = candidate;
                }
            }
            return best;
        }

        private static int ChooseVersion(string text)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);
            int bits = 4 + 8 + bytes.Length * 8;
            for (int v = 3; v <= 6; v++)
            {
                int dataCw = VersionL[v - 3, 0] - VersionL[v - 3, 1] * VersionL[v - 3, 2];
                if (bits <= dataCw * 8 - 4) return v;
            }
            return 6;
        }

        private static byte[] BuildDataCodewords(string text, int dataCw)
        {
            byte[] bytes = System.Text.Encoding.UTF8.GetBytes(text);
            List<byte> bits = new List<byte>();
            AddBits(bits, 0x4, 4);                 // byte mode
            AddBits(bits, bytes.Length, 8);        // length (8 bits for v<=9)
            foreach (byte b in bytes) AddBits(bits, b, 8);

            int cap = dataCw * 8;
            int term = Math.Min(4, cap - bits.Count);
            for (int i = 0; i < term; i++) bits.Add(0);
            while (bits.Count % 8 != 0) bits.Add(0);

            byte pad = 0xEC;
            while (bits.Count / 8 < dataCw)
            {
                AddBits(bits, pad, 8);
                pad = (byte)(pad == 0xEC ? 0x11 : 0xEC);
            }

            byte[] outBytes = new byte[dataCw];
            for (int i = 0; i < dataCw; i++)
            {
                int v = 0;
                for (int j = 0; j < 8; j++) v = (v << 1) | bits[i * 8 + j];
                outBytes[i] = (byte)v;
            }
            return outBytes;
        }

        private static void AddBits(List<byte> bits, int value, int count)
        {
            for (int i = count - 1; i >= 0; i--) bits.Add((byte)((value >> i) & 1));
        }

        private static byte[] CodewordsToBits(byte[] codewords, int total, int version)
        {
            int remainder = RemainderBits(version);
            byte[] bits = new byte[total * 8 + remainder];
            for (int i = 0; i < total; i++)
                for (int j = 0; j < 8; j++)
                    bits[i * 8 + j] = (byte)((codewords[i] >> (7 - j)) & 1);
            return bits;
        }

        private static int RemainderBits(int version)
        {
            return 7; // versions 2-6 all have 7 remainder bits
        }

        // ---- Function patterns ----
        private static void PlaceFunctionPatterns(bool[,] m, int version)
        {
            int size = SizeOf(version);
            PlaceFinder(m, 0, 0);
            PlaceFinder(m, size - 7, 0);
            PlaceFinder(m, 0, size - 7);

            for (int i = 8; i < size - 8; i++)
            {
                bool bit = i % 2 == 0;
                m[6, i] = bit;
                m[i, 6] = bit;
            }

            int[] centers = AlignmentCenters(version);
            foreach (int r in centers)
                foreach (int c in centers)
                {
                    if ((r < 9 && c < 9) || (r < 9 && c >= size - 8) || (r >= size - 8 && c < 9)) continue;
                    PlaceAlignment(m, r, c);
                }

            m[size - 8, 8] = true; // dark module
        }

        private static void PlaceFinder(bool[,] m, int row, int col)
        {
            for (int r = 0; r < 7; r++)
                for (int c = 0; c < 7; c++)
                {
                    bool dark = r == 0 || r == 6 || c == 0 || c == 6 || (r >= 2 && r <= 4 && c >= 2 && c <= 4);
                    m[row + r, col + c] = dark;
                }
            // separator (light) is implicit false.
        }

        private static void PlaceAlignment(bool[,] m, int centerR, int centerC)
        {
            for (int r = -2; r <= 2; r++)
                for (int c = -2; c <= 2; c++)
                    m[centerR + r, centerC + c] = Math.Max(Math.Abs(r), Math.Abs(c)) != 1;
        }

        private static bool IsFunction(bool[,] m, int row, int col, int version)
        {
            int size = m.GetLength(0);
            if (row <= 8 && col <= 8) return true;           // top-left finder + copy1 format
            if (row <= 8 && col >= size - 8) return true;   // top-right finder + copy2 format
            if (row >= size - 8 && col <= 8) return true;   // bottom-left finder + copy2 format + dark module
            if (row == 6 || col == 6) return true;          // timing
            int[] centers = AlignmentCenters(version);
            foreach (int r in centers)
                foreach (int c in centers)
                {
                    if ((r < 9 && c < 9) || (r < 9 && c >= size - 8) || (r >= size - 8 && c < 9)) continue;
                    if (Math.Abs(row - r) <= 2 && Math.Abs(col - c) <= 2) return true;
                }
            return false;
        }

        private static void PlaceData(bool[,] m, byte[] bits, int version)
        {
            int size = m.GetLength(0);
            int bit = 0;
            int col = size - 1;
            bool upward = true;
            while (col > 0)
            {
                if (col == 6) col--;
                for (int i = 0; i < size; i++)
                {
                    int row = upward ? size - 1 - i : i;
                    for (int dc = 0; dc < 2; dc++)
                    {
                        int c = col - dc;
                        if (IsFunction(m, row, c, version)) continue;
                        m[row, c] = bit < bits.Length && bits[bit] == 1;
                        bit++;
                    }
                }
                upward = !upward;
                col -= 2;
            }
        }

        // ---- Masking ----
        private static bool[,] ApplyMask(bool[,] m, int mask, int version)
        {
            int size = m.GetLength(0);
            bool[,] r = (bool[,])m.Clone();
            for (int row = 0; row < size; row++)
                for (int col = 0; col < size; col++)
                {
                    if (IsFunction(m, row, col, version)) continue;
                    if (MaskBit(mask, row, col)) r[row, col] = !r[row, col];
                }
            return r;
        }

        private static bool MaskBit(int mask, int row, int col)
        {
            switch (mask)
            {
                case 0: return (row + col) % 2 == 0;
                case 1: return row % 2 == 0;
                case 2: return col % 3 == 0;
                case 3: return (row + col) % 3 == 0;
                case 4: return ((row / 2) + (col / 3)) % 2 == 0;
                case 5: return (row * col) % 2 + (row * col) % 3 == 0;
                case 6: return ((row * col) % 2 + (row * col) % 3) % 2 == 0;
                case 7: return ((row + col) % 2 + (row * col) % 3) % 2 == 0;
                default: return false;
            }
        }

        private static int Penalty(bool[,] m)
        {
            int size = m.GetLength(0);
            int p = 0;
            for (int row = 0; row < size; row++)
            {
                int run = 1;
                for (int col = 1; col < size; col++)
                {
                    if (m[row, col] == m[row, col - 1]) run++;
                    else { if (run >= 5) p += 3 + (run - 5); run = 1; }
                }
                if (run >= 5) p += 3 + (run - 5);
            }
            for (int col = 0; col < size; col++)
            {
                int run = 1;
                for (int row = 1; row < size; row++)
                {
                    if (m[row, col] == m[row - 1, col]) run++;
                    else { if (run >= 5) p += 3 + (run - 5); run = 1; }
                }
                if (run >= 5) p += 3 + (run - 5);
            }
            for (int r = 0; r < size - 1; r++)
                for (int c = 0; c < size - 1; c++)
                    if (m[r, c] == m[r, c + 1] && m[r, c] == m[r + 1, c] && m[r, c] == m[r + 1, c + 1]) p += 3;
            return p;
        }

        // ---- Format info (ECC L = 01, 3-bit mask), BCH(15,5), XOR 0x5412 ----
        private static int FormatBits(int mask)
        {
            int data = (0x1 << 3) | mask;
            int rem = data << 10;
            int g = 0x537;
            for (int i = 14; i >= 10; i--)
            {
                if ((rem & (1 << i)) != 0) rem ^= g << (i - 10);
            }
            return ((data << 10) | rem) ^ 0x5412;
        }

        private static void PlaceFormatInfo(bool[,] m, int mask, int version)
        {
            int size = SizeOf(version);
            int fmt = FormatBits(mask);

            // Copy 1 around top-left finder, bit 14 (MSB) first.
            int[] r1 = { 8, 8, 8, 8, 8, 8, 8, 8, 7, 5, 4, 3, 2, 1, 0 };
            int[] c1 = { 0, 1, 2, 3, 4, 5, 7, 8, 8, 8, 8, 8, 8, 8, 8 };
            for (int i = 0; i < 15; i++)
                m[r1[i], c1[i]] = ((fmt >> (14 - i)) & 1) != 0;

            // Copy 2 split between top-right and bottom-left.
            int[] r2 = { size - 1, size - 2, size - 3, size - 4, size - 5, size - 6, size - 7, 8, 8, 8, 8, 8, 8, 8, 8 };
            int[] c2 = { 8, 8, 8, 8, 8, 8, 8, size - 8, size - 7, size - 6, size - 5, size - 4, size - 3, size - 2, size - 1 };
            for (int i = 0; i < 15; i++)
                m[r2[i], c2[i]] = ((fmt >> (14 - i)) & 1) != 0;
        }

        // ---- WPF rendering ----
        // Renders the matrix into a Grid of Rectangle modules with a 4-module quiet zone
        // (QR spec requires the light margin for scanners to find the symbol). moduleSize is in
        // device-independent pixels; the returned Grid is (size + 8) modules wide.
        public static FrameworkElement Render(bool[,] matrix, Brush darkColor, Brush lightColor, double moduleSize)
        {
            int size = matrix.GetLength(0);
            const int quiet = 4;
            int total = size + quiet * 2;
            Grid g = new Grid();
            g.Width = total * moduleSize;
            g.Height = total * moduleSize;
            g.Background = lightColor;
            for (int r = 0; r < total; r++)
                g.RowDefinitions.Add(new RowDefinition { Height = new GridLength(moduleSize) });
            for (int c = 0; c < total; c++)
                g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(moduleSize) });
            for (int r = 0; r < size; r++)
                for (int c = 0; c < size; c++)
                {
                    if (!matrix[r, c]) continue;
                    Rectangle rect = new Rectangle();
                    rect.Fill = darkColor;
                    Grid.SetRow(rect, r + quiet);
                    Grid.SetColumn(rect, c + quiet);
                    g.Children.Add(rect);
                }
            return g;
        }
    }


    public class HardwareReport
    {
        public string Cpu { get; set; }
        public string CpuName { get; set; }
        public string CpuDetail { get; set; }
        public string Gpu { get; set; }
        public string GpuName { get; set; }
        public string GpuDetail { get; set; }
        public string Ram { get; set; }
        public string RamName { get; set; }
        public string RamDetail { get; set; }
        public string StorageSummary { get; set; }
        public string StorageName { get; set; }
        public string StorageDetail { get; set; }
        public string Os { get; set; }
        public string BoardManufacturer { get; set; }
        public string BoardProduct { get; set; }
        public string BiosVersion { get; set; }
        public string BiosDate { get; set; }
        public string BootMode { get; set; }
        public string ChassisType { get; set; }
        public string BatterySummary { get; set; }
        public bool HasBattery { get; set; }
        public List<DiskItem> Disks { get; set; }
        
        public int BadBlockTotal { get; set; }
        public string BadBlockTargetDevice { get; set; }
        public long LatestRecordId { get; set; }
        public DateTime LatestRecordTime { get; set; }
        public string SampleEventMessage { get; set; }
        public int KernelPowerEvents { get; set; }
        public int DiskIoErrors { get; set; }
        public int AppCrashes { get; set; }
        public string AppCrashSummary { get; set; }
        public string MiniDumpSummary { get; set; }
        public bool SplitBootDetected { get; set; }
        public string SplitBootDetails { get; set; }
        public int WheaCount { get; set; }
        public string WheaSummary { get; set; }
        public long WheaLatestRecordId { get; set; }
        public DateTime WheaLatestTime { get; set; }
        public string WheaLatestMessage { get; set; }
        public int BugCheckCount { get; set; }
        public string BugCheckSummary { get; set; }
        public string BugCheckStopCode { get; set; }
        public DateTime BugCheckLatestTime { get; set; }
        public int DisplayTdrCount { get; set; }
        public string DisplayTdrSummary { get; set; }
        public DateTime Timestamp { get; set; }

        // Advanced System Health & Hardware Integrity
        public double SystemReliabilityScore { get; set; }
        public string SystemReliabilitySummary { get; set; }
        public int CpuThrottleCount { get; set; }
        public DateTime LatestThrottleTime { get; set; }
        public List<string> PnpDeviceErrors { get; set; }
        public bool MemDiagRan { get; set; }
        public bool MemDiagFailed { get; set; }
        public DateTime MemDiagLatestTime { get; set; }
        public int LowMemoryEvents { get; set; }
        public string LowMemorySummary { get; set; }
        public bool CmosClockDriftDetected { get; set; }
        public List<string> DeadAutoServices { get; set; }
        public string TpmStatus { get; set; }
        public string SecureBootStatus { get; set; }
        public string BitLockerStatus { get; set; }
        public bool SsdTrimEnabled { get; set; }
        public int NtfsCorruptionEvents { get; set; }
        public double BatteryWearPercent { get; set; }
        public int BatteryCycleCount { get; set; }
        public long NetworkPacketErrors { get; set; }
        public long NetworkPacketDiscards { get; set; }

        // Phase 1: CPU topology + virtualization
        public string CpuSocket { get; set; }
        public int CpuCoreCount { get; set; }
        public int CpuThreadCount { get; set; }
        public bool HypervisorPresent { get; set; }
        public string GpuPcieLink { get; set; }
        public bool GpuPcieCrippled { get; set; }
        public string GpuPcieDetail { get; set; }

        // Phase 1: per-DIMM inventory + XMP/EXPO lock
        public List<string> RamModules { get; set; }
        public bool XmpDisabledSuspected { get; set; }
        public uint RamRatedSpeed { get; set; }
        public uint RamConfiguredSpeed { get; set; }
        public string XmpSummary { get; set; }

        // Phase 1: Kernel-Power 41 BugcheckCode decode
        public string KernelPowerStopCode { get; set; }
        public string KernelPowerVerdict { get; set; }
        public DateTime KernelPowerLatestTime { get; set; }

        // Phase 1: SMART source (MSFT_StorageReliabilityCounter vs Win32_DiskDrive fallback)
        public string SmartSource { get; set; }

        // Phase 1: Minidump count + latest timestamp (structured)
        public int MiniDumpCount { get; set; }
        public DateTime MiniDumpLatestTime { get; set; }

        // Phase 2: pcfix Reliability Score (deterministic, 0-100). New properties for the score.
        public int WheaCount7d { get; set; }
        public int PcfixScore { get; set; }
        public string PcfixScoreLabel { get; set; }
        public List<string> PcfixDeductions { get; set; }

        // Phase 4: three-tier severity classification + operational status reality check.
        public string PcfixTier { get; set; }
        public string OperationalStatusText { get; set; }
        public string VerdictLabel { get; set; }
        public string VerdictAdvice { get; set; }
        public string SoftwareStability { get; set; }

        public HardwareReport()
        {
            Cpu = "Querying...";
            CpuName = "CPU / Processor";
            CpuDetail = "Querying...";
            Gpu = "Querying...";
            GpuName = "GPU / Graphics";
            GpuDetail = "Querying...";
            Ram = "Querying...";
            RamName = "System Memory";
            RamDetail = "Querying...";
            StorageSummary = "Querying...";
            StorageName = "Storage Architecture";
            StorageDetail = "Querying...";
            Os = "Querying...";
            BoardManufacturer = "Unknown";
            BoardProduct = "Unknown";
            BiosVersion = "Unknown";
            BiosDate = "";
            BootMode = "Unknown";
            ChassisType = "Unknown";
            BatterySummary = "";
            HasBattery = false;
            Disks = new List<DiskItem>();
            MiniDumpSummary = "None detected (System Nominal)";
            AppCrashSummary = "None detected";
            WheaSummary = "None detected";
            BugCheckSummary = "None detected";
            BugCheckStopCode = "";
            DisplayTdrSummary = "None detected";
            Timestamp = DateTime.Now;

            SystemReliabilityScore = -1;
            SystemReliabilitySummary = "Not recorded";
            PnpDeviceErrors = new List<string>();
            LowMemorySummary = "None detected";
            DeadAutoServices = new List<string>();
            TpmStatus = "Not detected";
            SecureBootStatus = "Unknown";
            BitLockerStatus = "Unencrypted";
            SsdTrimEnabled = true;
            BatteryWearPercent = -1;
            BatteryCycleCount = -1;

            CpuSocket = "";
            GpuPcieLink = "";
            GpuPcieDetail = "";
            RamModules = new List<string>();
            XmpSummary = "";
            KernelPowerStopCode = "";
            KernelPowerVerdict = "";
            SmartSource = "Unavailable";
            PcfixScoreLabel = "Not scored";
            PcfixDeductions = new List<string>();
            PcfixTier = "Unknown";
            OperationalStatusText = "";
            VerdictLabel = "";
            VerdictAdvice = "";
            SoftwareStability = "No application crashes recorded";
        }

        // Tier 1 critical: verified physical hardware failure only. Bad block read retries,
        // split-boot, XMP-off, app crashes, and CMOS drift are explicitly NOT here.
        public bool HasTier1HardwareFault
        {
            get
            {
                if (WheaCount > 0) return true;
                if (MemDiagFailed) return true;
                if (Disks.Exists(d => d.IsSsdDeath)) return true;
                if (KernelPowerStopCode != null && KernelPowerStopCode.Length > 0)
                {
                    if (KernelPowerStopCode.IndexOf("0x124", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                    if (KernelPowerStopCode.IndexOf("0x7A", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                    if (KernelPowerStopCode.IndexOf("0x1A", StringComparison.OrdinalIgnoreCase) >= 0) return true;
                }
                return false;
            }
        }

        // Tier 2 maintenance: degraded but not crashing. Read retries, thermals, driver TDR.
        public bool HasTier2Maintenance
        {
            get
            {
                return BadBlockTotal > 0
                    || CpuThrottleCount > 0
                    || DisplayTdrCount > 0
                    || NtfsCorruptionEvents > 0
                    || (Disks.Exists(d => d.Status != "OK" && !d.IsSsdDeath))
                    || (Disks.Exists(d => d.SmartHealthStatus == "Warning"));
            }
        }

        // Kept for back-compat: the UI alert card treats tier 1 as the red "critical" branch.
        public bool HasCriticalHardwareFailure
        {
            get { return HasTier1HardwareFault; }
        }

        public bool HasWarningCondition
        {
            get
            {
                return HasTier2Maintenance
                    || SplitBootDetected
                    || XmpDisabledSuspected
                    || CmosClockDriftDetected
                    || BugCheckCount > 0
                    || PnpDeviceErrors.Count > 0
                    || LowMemoryEvents > 0
                    || DeadAutoServices.Count > 0
                    || !SsdTrimEnabled
                    || AppCrashes > 0
                    || (SystemReliabilityScore >= 0 && SystemReliabilityScore < 5.0);
            }
        }

        // =====================================================================
        // Phase 2: Deterministic pcfix Reliability Score (0-100)
        // =====================================================================
        // Deductions are applied once per category, capped at 100. The score
        // is independent of the Windows Reliability Index (which is an opaque
        // composite metric); this one uses only the raw telemetry already
        // collected in PerformDeepHardwareScan().
        //
        //   -40  WHEA machine check events (Event 18/19/47)
        //   -35  Windows Memory Diagnostic failure (Event 1201) or SSD death
        //   -30  Kernel-Power 41 bugcheck 0x124/0x7A/0x1A
        //   -20  disk bad block read retries (Event 7/51/153)
        //   -12  CPU thermal/firmware throttling (Event 37)
        //   -10  display driver TDR resets (Event 4101)
        //    -5  split-boot layout / XMP off / CMOS drift (advisories)
        //
        // Called once after PerformDeepHardwareScan() populates all fields.
        // Detects RAM sticks populated in the same memory channel (single-channel mode with 2+ sticks),
        // or a single stick in a board with 2+ slots. Parses DeviceLocator text such as
        // "ChannelA-DIMM0", "DIMM_A1", "Controller0-ChannelB". Returns "" when no issue or unparseable.
        public string GetRamChannelIssue()
        {
            if (RamModules == null || RamModules.Count == 0) return "";
            List<string> channels = new List<string>();
            int parsed = 0;
            foreach (string m in RamModules)
            {
                string loc = m.IndexOf(':') > 0 ? m.Substring(0, m.IndexOf(':')) : m;
                Match mc = Regex.Match(loc, @"Channel\s*([A-H])", RegexOptions.IgnoreCase);
                if (!mc.Success) mc = Regex.Match(loc, @"DIMM[_\s-]?([A-H])\d", RegexOptions.IgnoreCase);
                if (!mc.Success) continue;
                parsed++;
                string ch = mc.Groups[1].Value.ToUpperInvariant();
                if (!channels.Contains(ch)) channels.Add(ch);
            }
            if (RamModules.Count >= 2 && parsed == RamModules.Count && channels.Count == 1)
            {
                return string.Format("RAM unseated from dual channel: {0} sticks share Channel {1}. Move one stick to the other channel slot (check board manual, usually A2 + B2).", RamModules.Count, channels[0]);
            }
            if (RamModules.Count == 1)
            {
                return "RAM in single channel: only 1 stick detected. Add a matched second stick, or reseat if 2 are installed.";
            }
            return "";
        }

        public void CalculatePcfixScore()
        {
            int score = 100;
            PcfixDeductions = new List<string>();

            // ---- TIER 1: CRITICAL HARDWARE FAULTS (verified physical failure) ----
            bool wheaFault = WheaCount > 0;
            bool memFault = MemDiagFailed;
            bool kpCritical = false;
            if (KernelPowerStopCode != null)
            {
                if (KernelPowerStopCode.IndexOf("0x124", StringComparison.OrdinalIgnoreCase) >= 0) kpCritical = true;
                if (KernelPowerStopCode.IndexOf("0x7A", StringComparison.OrdinalIgnoreCase) >= 0) kpCritical = true;
                if (KernelPowerStopCode.IndexOf("0x1A", StringComparison.OrdinalIgnoreCase) >= 0) kpCritical = true;
            }
            bool ssdDeath = false;
            foreach (DiskItem d in Disks)
            {
                if (d.IsSsdDeath) { ssdDeath = true; break; }
            }

            if (wheaFault)
            {
                score -= 40;
                PcfixDeductions.Add(string.Format("-40: {0} WHEA machine check events (Event 18/19/47). CPU bus, cache or PCIe parity fault.", WheaCount));
            }
            if (memFault)
            {
                score -= 35;
                PcfixDeductions.Add("-35: Windows Memory Diagnostic failure (Event 1201). Defective RAM stick.");
            }
            if (ssdDeath)
            {
                score -= 35;
                PcfixDeductions.Add("-35: SSD severe wear or predictive failure. Drive reported read-only or SMART wear >= 95%.");
            }
            if (kpCritical)
            {
                score -= 30;
                PcfixDeductions.Add(string.Format("-30: Kernel-Power 41 bugcheck {0}. Power, memory or storage hardware fault.", KernelPowerStopCode));
            }

            // ---- TIER 2: MAINTENANCE & DEGRADED STORAGE (actionable, not crash-critical) ----
            if (BadBlockTotal > 0 && !ssdDeath)
            {
                score -= 20;
                PcfixDeductions.Add(string.Format("-20: {0:N0} bad block read retries logged (Event 7/51/153). Isolated bad sectors, not disk death.", BadBlockTotal));
            }
            if (CpuThrottleCount > 0)
            {
                score -= 12;
                PcfixDeductions.Add(string.Format("-12: {0} CPU thermal/firmware throttle events (Event 37).", CpuThrottleCount));
            }
            if (DisplayTdrCount > 0)
            {
                score -= 10;
                PcfixDeductions.Add(string.Format("-10: {0} display driver resets (Event 4101).", DisplayTdrCount));
            }

            // ---- TIER 3: CONFIGURATION & OPTIMIZATION ADVISORIES (non-critical) ----
            if (SplitBootDetected)
            {
                score -= 5;
                PcfixDeductions.Add("-5: Split-boot layout (boot files on a secondary disk). Configuration note, not a fault.");
            }
            if (XmpDisabledSuspected)
            {
                score -= 5;
                PcfixDeductions.Add(string.Format("-5: RAM at {0} MT/s, modules rated {1} MT/s (XMP/EXPO off). Performance advisory.", RamConfiguredSpeed, RamRatedSpeed));
            }
            if (CmosClockDriftDetected)
            {
                score -= 5;
                PcfixDeductions.Add("-5: RTC clock drift. Replace CR2032 coin cell on the motherboard.");
            }

            if (score < 0) score = 0;
            PcfixScore = score;

            // Score scale & verdict normalization.
            if (score >= 85)
            {
                PcfixScoreLabel = "Optimal / Stable";
                PcfixTier = "TIER 3";
            }
            else if (score >= 65)
            {
                PcfixScoreLabel = "Healthy / Maintenance Recommended";
                PcfixTier = "TIER 3";
            }
            else if (score >= 45)
            {
                PcfixScoreLabel = "Degraded / Attention Required";
                PcfixTier = "TIER 2";
            }
            else
            {
                PcfixScoreLabel = "Critical Hardware Fault";
                PcfixTier = "TIER 1";
            }

            // Tier verdict + plain-language operational status reality check.
            if (HasTier1HardwareFault)
            {
                VerdictLabel = "CRITICAL HARDWARE FAILURE DETECTED";
                VerdictAdvice = "Replace defective component before total failure. Back up critical personal files immediately.";
                OperationalStatusText = "OPERATIONAL STATUS: System stability at critical risk. Hardware failure confirmed.";
                PcfixTier = "TIER 1";
            }
            else if (HasTier2Maintenance)
            {
                OperationalStatusText = "OPERATIONAL STATUS: System is currently operational. No immediate motherboard or CPU failure. Follow standard maintenance steps below.";
                PcfixTier = "TIER 2";
                if (BadBlockTotal > 0)
                {
                    VerdictLabel = "Storage Read Errors Logged";
                    VerdictAdvice = "File corruption or isolated bad sectors detected on a disk. Run chkdsk /r and back up the affected partition.";
                }
                else if (CpuThrottleCount > 0)
                {
                    VerdictLabel = "CPU Thermal / Firmware Throttling Logged";
                    VerdictAdvice = "Clean cooler heatsink or re-apply thermal paste.";
                }
                else if (DisplayTdrCount > 0)
                {
                    VerdictLabel = "Graphics Driver Timeout";
                    VerdictAdvice = "Clean reinstall the GPU driver using DDU.";
                }
                else
                {
                    VerdictLabel = "Maintenance Recommended";
                    VerdictAdvice = "Follow standard maintenance steps below.";
                }
            }
            else
            {
                OperationalStatusText = "OPERATIONAL STATUS: System is currently operational. No immediate motherboard or CPU failure. Follow standard maintenance steps below.";
                PcfixTier = "TIER 3";
                if (SplitBootDetected)
                {
                    VerdictLabel = "Boot Configuration Note: Split-Boot Layout";
                    VerdictAdvice = "System boots and operates normally. Boot files reside on a secondary drive. Ensure both drives stay connected.";
                }
                else if (XmpDisabledSuspected)
                {
                    VerdictLabel = "Performance Advisory: XMP/EXPO Disabled";
                    VerdictAdvice = "Enable XMP/EXPO in BIOS for a memory bandwidth boost (optional).";
                }
                else
                {
                    VerdictLabel = "System Nominal";
                    VerdictAdvice = "No hardware faults detected. Minor optimizations optional.";
                }
            }

            // Software stability is a separate line item, never a hardware score deduction.
            if (AppCrashes > 0)
            {
                SoftwareStability = string.Format("{0} routine application crash(es): {1}. Reinstall or update the affected program.", AppCrashes, AppCrashSummary);
            }
            else
            {
                SoftwareStability = "No application crashes recorded.";
            }
        }

        // =====================================================================
        // Phase 2: Markdown Report for pcfix technicians
        // =====================================================================
        // Escapes a value for a Markdown table cell: pipes split columns, newlines break rows.
        private static string MdCell(string v)
        {
            if (string.IsNullOrEmpty(v)) return "N/A";
            return v.Replace("|", "\\|").Replace("\r", " ").Replace("\n", " ");
        }

        public string GenerateMarkdownReport()
        {
            StringBuilder md = new StringBuilder();
            md.AppendLine("# pcfix Hardware Diagnosis Snapshot");
            md.AppendLine();
            md.AppendLine(string.Format("**Scanned:** {0:yyyy-MM-dd HH:mm:ss}  ", Timestamp));
            md.AppendLine(string.Format("**OS:** {0}  ", Os));
            if (!string.IsNullOrEmpty(BoardProduct) && BoardProduct != "Unknown")
            {
                md.AppendLine(string.Format("**Board:** {0} {1} | BIOS {2} ({3})  ", BoardManufacturer, BoardProduct, BiosVersion, BootMode));
            }
            md.AppendLine(string.Format("**pcfix Score:** {0} / 100 ({1}) [{2}]", PcfixScore, PcfixScoreLabel, PcfixTier));
            if (!string.IsNullOrEmpty(OperationalStatusText))
            {
                md.AppendLine(string.Format("**{0}**", OperationalStatusText));
            }
            if (!string.IsNullOrEmpty(VerdictLabel))
            {
                md.AppendLine(string.Format("**Verdict:** {0}", VerdictLabel));
                md.AppendLine(string.Format("**Advice:** {0}", VerdictAdvice));
            }
            md.AppendLine();

            // 4-Block Matrix
            md.AppendLine("## Hardware Matrix");
            md.AppendLine();
            md.AppendLine("| Component | Summary |");
            md.AppendLine("|-----------|---------|");
            md.AppendLine(string.Format("| CPU | {0} |", MdCell(Cpu)));
            md.AppendLine(string.Format("| GPU | {0} |", MdCell(Gpu)));
            md.AppendLine(string.Format("| RAM | {0} |", MdCell(Ram)));
            md.AppendLine(string.Format("| Storage | {0} |", MdCell(StorageSummary)));
            md.AppendLine();

            // Disk Detail
            if (Disks.Count > 0)
            {
                md.AppendLine("## Disk Health");
                md.AppendLine();
                foreach (DiskItem d in Disks)
                {
                    string vols = d.Volumes.Count > 0 ? string.Join(", ", d.Volumes.ToArray()) : "No letters";
                    string role = "";
                    if (d.IsWindowsOs && d.IsBootloader) role = " [Windows OS + EFI Boot]";
                    else if (d.IsWindowsOs) role = " [Windows OS]";
                    else if (d.IsBootloader) role = " [EFI Bootloader]";
                    md.AppendLine(string.Format("- **Disk {0}:** {1} ({2:F0} GB){3} | {4} | {5}", d.Index, d.Model, d.SizeGb, role, vols, d.GetHealthBadge()));
                    if (d.SmartHealthStatus != "Unknown")
                    {
                        md.AppendLine(string.Format("  - SMART: {0} | Wear: {1} | Temp: {2} | Hours: {3} | Errors: {4}",
                            d.SmartHealthStatus,
                            d.SmartWearPercent.HasValue ? d.SmartWearPercent.Value + "%" : "N/A",
                            d.SmartTemperatureCelsius.HasValue ? d.SmartTemperatureCelsius.Value + " C" : "N/A",
                            d.SmartPowerOnHours.HasValue ? d.SmartPowerOnHours.Value.ToString() : "N/A",
                            d.SmartReadErrorsUncorrected.HasValue ? d.SmartReadErrorsUncorrected.Value.ToString() : "N/A"));
                    }
                }
                md.AppendLine();
            }

            // Score Breakdown
            if (PcfixDeductions.Count > 0)
            {
                md.AppendLine("## Score Deductions");
                md.AppendLine();
                foreach (string ded in PcfixDeductions)
                {
                    md.AppendLine("- " + ded);
                }
                md.AppendLine();
            }

            // Critical Alerts (tier 1 physical failures only)
            List<string> alerts = new List<string>();
            if (BadBlockTotal > 0 && !Disks.Exists(d => d.IsSsdDeath))
            {
                alerts.Add(string.Format("Storage read retries: {0:N0} logged on {1}. Run chkdsk /r and back up the affected partition.", BadBlockTotal, BadBlockTargetDevice));
            }
            foreach (DiskItem d in Disks)
            {
                if (d.IsSsdDeath)
                {
                    alerts.Add(string.Format("SSD failure: Disk {0} ({1}) reports severe wear or predictive failure. Replace drive.", d.Index, d.Model));
                }
                else if ((d.SmartReadErrorsUncorrected ?? 0) > 0)
                {
                    alerts.Add(string.Format("Disk {0} ({1}) has {2} uncorrected read errors. Data loss risk.", d.Index, d.Model, d.SmartReadErrorsUncorrected));
                }
            }
            if (WheaCount > 0) alerts.Add(string.Format("WHEA hardware errors: {0} machine check events. CPU, RAM or PCIe bus fault.", WheaCount));
            if (MemDiagFailed) alerts.Add("Windows Memory Diagnostic detected defective RAM.");
            if (NtfsCorruptionEvents > 0) alerts.Add(string.Format("NTFS corruption: {0} volume directory errors. Run chkdsk /f.", NtfsCorruptionEvents));
            if (SplitBootDetected) alerts.Add(SplitBootDetails);
            if (XmpDisabledSuspected) alerts.Add(XmpSummary);
            string chIssue = GetRamChannelIssue();
            if (chIssue.Length > 0) alerts.Add(chIssue);
            if (CpuThrottleCount > 0) alerts.Add(string.Format("CPU throttled {0} times. Thermal paste or cooler issue.", CpuThrottleCount));
            if (KernelPowerEvents > 0) alerts.Add(string.Format("{0} unexpected shutdown(s) in 7 days (Kernel-Power 41).", KernelPowerEvents));
            if (DisplayTdrCount > 0) alerts.Add(string.Format("Display driver reset {0} times ({1}). Clean reinstall GPU driver with DDU.", DisplayTdrCount, DisplayTdrSummary));
            if (BugCheckCount > 0) alerts.Add(string.Format("BSOD: {0}.", BugCheckSummary));
            if (!string.IsNullOrEmpty(KernelPowerStopCode)) alerts.Add("Last Kernel-Power stop code: " + KernelPowerStopCode);
            if (PnpDeviceErrors.Count > 0) alerts.Add(string.Format("Device Manager: {0} hardware faults.", PnpDeviceErrors.Count));

            if (alerts.Count > 0)
            {
                md.AppendLine("## Critical Alerts");
                md.AppendLine();
                foreach (string a in alerts)
                {
                    md.AppendLine("- " + a);
                }
                md.AppendLine();
            }

            // Physical Fix Steps
            md.AppendLine("## Immediate Physical Fix Steps");
            md.AppendLine();
            md.AppendLine("Try these non-destructive steps before reinstalling Windows or replacing parts:");
            md.AppendLine();
            int step = 1;
            if (BadBlockTotal > 0 || Disks.Exists(d => (d.SmartReadErrorsUncorrected ?? 0) > 0))
            {
                md.AppendLine(string.Format("{0}. **Back up data now.** Copy personal files to an external drive before the failing disk stops responding.", step++));
                md.AppendLine(string.Format("{0}. **Reseat SATA/NVMe cables.** Power off, unplug the data and power cables from the failing disk, blow out dust, reconnect firmly.", step++));
                md.AppendLine(string.Format("{0}. **Try a different SATA port or slot.** Eliminates a bad port as the cause.", step++));
            }
            if (WheaCount > 0 || MemDiagFailed || GetRamChannelIssue().Length > 0)
            {
                md.AppendLine(string.Format("{0}. **Reseat RAM sticks.** Power off, press the DIMM clips, pull each stick, blow out the slot, reinsert until they click.", step++));
                md.AppendLine(string.Format("{0}. **Test one stick at a time.** Boot with each DIMM alone to isolate the faulty module.", step++));
            }
            if (CpuThrottleCount > 0)
            {
                md.AppendLine(string.Format("{0}. **Clean CPU cooler and reapply thermal paste.** Throttling usually means the CPU hits its thermal limit.", step++));
                md.AppendLine(string.Format("{0}. **Verify CPU fan connector.** Make sure the fan header is plugged into CPU_FAN, not SYS_FAN.", step++));
            }
            if (XmpDisabledSuspected)
            {
                md.AppendLine(string.Format("{0}. **Enable XMP/EXPO in BIOS.** Boot into BIOS (Del/F2), enable the XMP or EXPO profile, save and exit.", step++));
            }
            if (SplitBootDetected)
            {
                md.AppendLine(string.Format("{0}. **Keep both drives connected.** The EFI System Partition is on a separate disk. Removing it will make Windows unbootable.", step++));
            }
            if (DisplayTdrCount > 0)
            {
                md.AppendLine(string.Format("{0}. **Clean reinstall the GPU driver using DDU.** Download Display Driver Uninstaller, uninstall in Safe Mode, reinstall the latest driver.", step++));
            }
            if (CmosClockDriftDetected)
            {
                md.AppendLine(string.Format("{0}. **Replace CMOS battery.** The CR2032 coin cell on the motherboard is dead. Replace it and reconfigure BIOS settings.", step++));
            }
            if (step == 1)
            {
                md.AppendLine("No immediate physical action needed. System is nominal.");
            }
            md.AppendLine();

            // Event Summary
            md.AppendLine("## Event Log Summary");
            md.AppendLine();
            md.AppendLine(string.Format("- Bad block read retries (Event 7/51/153): {0:N0}", BadBlockTotal));
            md.AppendLine(string.Format("- Kernel-Power 41 (7 days): {0}", KernelPowerEvents));
            md.AppendLine(string.Format("- WHEA (Event 18/19/47): {0} total, {1} in 7 days", WheaCount, WheaCount7d));
            md.AppendLine(string.Format("- BugCheck BSOD (Event 1001): {0}", BugCheckCount));
            md.AppendLine(string.Format("- Display TDR (Event 4101): {0}", DisplayTdrCount));
            md.AppendLine("- MiniDump: " + MiniDumpSummary);
            md.AppendLine();
            md.AppendLine("## Software Stability");
            md.AppendLine();
            md.AppendLine("- " + SoftwareStability);
            md.AppendLine();

            // Firmware and Security
            md.AppendLine("## Firmware and Security");
            md.AppendLine();
            md.AppendLine(string.Format("- TPM: {0}", TpmStatus));
            md.AppendLine(string.Format("- Secure Boot: {0}", SecureBootStatus));
            md.AppendLine(string.Format("- BitLocker: {0}", BitLockerStatus));
            md.AppendLine(string.Format("- SSD TRIM: {0}", SsdTrimEnabled ? "Enabled" : "Disabled"));
            if (HypervisorPresent) md.AppendLine("- Hypervisor: Present (Hyper-V / VBS / WSL2)");
            md.AppendLine();
            md.AppendLine("---");
            md.AppendLine("*Generated by pcfix desktop scanner*");

            return md.ToString();
        }

        // =====================================================================
        // Phase 2: Web Handoff URL for pcfix AI technician
        // =====================================================================
        // Builds a URL that pre-populates the web chat with a compact summary
        // of this machine's findings. The web side reads `?hw=` as the initial
        // user message. URL length is kept under ~2000 chars (IE11 / shared
        // link safe) by compressing to flags + one-liner per issue.
        public string BuildWebHandoffUrl()
        {
            string baseUrl = "https://pcfixtech.my.id/troubleshoot";
            StringBuilder q = new StringBuilder();
            q.Append("[pcfix scanner report]");
            q.Append(string.Format(" Score:{0}/100({1}).", PcfixScore, PcfixScoreLabel));

            // CPU
            q.Append(string.Format(" CPU:{0}", CpuName));
            if (CpuThrottleCount > 0) q.Append(string.Format(" THROTTLE:{0}", CpuThrottleCount));

            // RAM
            q.Append(string.Format(" RAM:{0}", Ram));
            if (XmpDisabledSuspected) q.Append(string.Format(" XMP:OFF({0}/{1})", RamConfiguredSpeed, RamRatedSpeed));

            // GPU
            q.Append(string.Format(" GPU:{0}", GpuName));
            if (DisplayTdrCount > 0) q.Append(string.Format(" TDR:{0}", DisplayTdrCount));

            // Storage
            foreach (DiskItem d in Disks)
            {
                q.Append(string.Format(" D{0}:{1}({2:F0}GB)", d.Index, d.Model, d.SizeGb));
                if (d.IsSsdDeath) q.Append("[FAIL]");
                else if (d.SmartHealthStatus == "Warning") q.Append("[WARN]");
                else if (d.BadBlockCount > 0) q.Append("[RETRY]");
                if (d.SmartWearPercent.HasValue && d.SmartWearPercent.Value >= 80) q.Append(string.Format("[WEAR:{0}%]", d.SmartWearPercent.Value));
            }
            if (SplitBootDetected) q.Append(" SPLITBOOT:YES");

            // Events
            if (KernelPowerEvents > 0) q.Append(string.Format(" KP41:{0}", KernelPowerEvents));
            if (WheaCount > 0) q.Append(string.Format(" WHEA:{0}", WheaCount));
            if (BugCheckCount > 0)
            {
                q.Append(string.Format(" BSOD:{0}", BugCheckCount));
                if (!string.IsNullOrEmpty(BugCheckStopCode)) q.Append(string.Format("({0})", BugCheckStopCode.Length > 30 ? BugCheckStopCode.Substring(0, 30) : BugCheckStopCode));
            }
            if (!string.IsNullOrEmpty(KernelPowerStopCode) && KernelPowerStopCode.Length > 2) q.Append(string.Format(" KP41Stop:{0}", KernelPowerStopCode.Length > 30 ? KernelPowerStopCode.Substring(0, 30) : KernelPowerStopCode));
            if (MemDiagFailed) q.Append(" MEMDIAG:FAIL");
            if (GetRamChannelIssue().Length > 0) q.Append(" RAMCH:SINGLE");
            if (NtfsCorruptionEvents > 0) q.Append(string.Format(" NTFS:{0}", NtfsCorruptionEvents));
            if (MiniDumpCount > 0) q.Append(string.Format(" DUMPS:{0}", MiniDumpCount));

            // OS and board
            q.Append(string.Format(" OS:{0}", Os));
            if (!string.IsNullOrEmpty(BoardProduct) && BoardProduct != "Unknown") q.Append(string.Format(" MB:{0} {1}", BoardManufacturer, BoardProduct));

            string query = q.ToString();
            // Truncate raw text; percent-encoding can grow it, final URL is re-checked below
            int maxQuery = 1400;
            if (query.Length > maxQuery) query = query.Substring(0, maxQuery);
            while (query.Length > 200 && Uri.EscapeDataString(query).Length > 1950) query = query.Substring(0, query.Length - 50);

            return baseUrl + "?hw=" + Uri.EscapeDataString(query);
        }

        // Phase 3 / Upgrade 3: compact handoff payload for the QR code. Base64 (URL-safe) of a
        // flag-delimited summary. Deliberately terse so the URL stays under ~105 bytes and the QR
        // fits in version 5 (33 modules). No gzip: gzip inflates payloads this small.
        public string BuildQrPayload()
        {
            StringBuilder q = new StringBuilder();
            q.Append("pcfix");
            q.Append(string.Format("|s{0}", PcfixScore));
            if (CpuThrottleCount > 0) q.Append(string.Format("|c{0}", CpuThrottleCount));
            q.Append(string.Format("|x{0}", XmpDisabledSuspected ? "1" : "0"));
            q.Append(string.Format("|d{0}", Disks.Count));
            foreach (DiskItem d in Disks)
            {
                string st = d.IsSsdDeath ? "F" : (d.SmartHealthStatus == "Warning" ? "W" : (d.BadBlockCount > 0 ? "R" : "O"));
                q.Append(string.Format("|d{0}{1}", d.Index, st));
                if (d.BadBlockCount > 0) q.Append(string.Format(";{0}", d.BadBlockCount));
            }
            if (SplitBootDetected) q.Append("|b1");
            if (KernelPowerEvents > 0) q.Append(string.Format("|k{0}", KernelPowerEvents));
            if (WheaCount7d > 0) q.Append(string.Format("|w{0}", WheaCount7d));
            if (BugCheckCount > 0) q.Append(string.Format("|g{0}", BugCheckCount));
            if (DisplayTdrCount > 0) q.Append(string.Format("|t{0}", DisplayTdrCount));
            if (NtfsCorruptionEvents > 0) q.Append(string.Format("|n{0}", NtfsCorruptionEvents));
            if (MemDiagFailed) q.Append("|m1");

            string s = q.ToString();
            string b64 = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(s));
            b64 = b64.Replace('+', '-').Replace('/', '_').TrimEnd('=');
            return "https://pcfixtech.my.id/troubleshoot?scan=" + b64;
        }

        public string ToFormattedPayload()
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("=== PCFIX HARDWARE REPORT ===");
            sb.AppendLine("TIMESTAMP: " + Timestamp.ToString("yyyy-MM-dd HH:mm:ss"));
            sb.AppendLine("OS: " + Os);
            sb.AppendLine(string.Format("PCFIX_SCORE: {0}/100 ({1}) [{2}]", PcfixScore, PcfixScoreLabel, PcfixTier));
            if (!string.IsNullOrEmpty(OperationalStatusText))
            {
                sb.AppendLine(OperationalStatusText);
            }
            if (!string.IsNullOrEmpty(VerdictLabel))
            {
                sb.AppendLine("VERDICT: " + VerdictLabel);
                sb.AppendLine("ADVICE: " + VerdictAdvice);
            }
            if (!string.IsNullOrEmpty(BoardProduct) && BoardProduct != "Unknown")
            {
                sb.AppendLine("BOARD: " + BoardManufacturer + " " + BoardProduct + " | BIOS " + BiosVersion + " (" + BootMode + ")");
            }
            sb.AppendLine("CPU: " + Cpu);
            sb.AppendLine("GPU: " + Gpu);
            sb.AppendLine("RAM: " + Ram);
            if (!string.IsNullOrEmpty(CpuSocket))
            {
                sb.AppendLine(string.Format("CPU_TOPOLOGY: {0} | {1} Cores / {2} Threads | Hypervisor: {3}", CpuSocket, CpuCoreCount, CpuThreadCount, HypervisorPresent ? "Present" : "None"));
            }
            if (RamModules.Count > 0)
            {
                sb.AppendLine("RAM_MODULES:");
                foreach (string m in RamModules) sb.AppendLine("  " + m);
            }
            if (!string.IsNullOrEmpty(XmpSummary))
            {
                sb.AppendLine((XmpDisabledSuspected ? "RAM_XMP: WARNING " : "RAM_XMP: ") + XmpSummary);
            }
            if (HasBattery)
            {
                sb.AppendLine("BATTERY: " + BatterySummary + " | CHASSIS: " + ChassisType);
            }
            else if (!string.IsNullOrEmpty(ChassisType) && ChassisType != "Unknown")
            {
                sb.AppendLine("CHASSIS: " + ChassisType);
            }

            if (SystemReliabilityScore >= 0)
            {
                sb.AppendLine();
                sb.AppendLine("SYSTEM_RELIABILITY_INDEX: " + SystemReliabilitySummary);
            }

            sb.AppendLine();
            sb.AppendLine("STORAGE_DISKS: (SMART source: " + SmartSource + ")");
            foreach (DiskItem d in Disks)
            {
                string vols = d.Volumes.Count > 0 ? string.Join(", ", d.Volumes.ToArray()) : "No letters assigned";
                string role = "";
                if (d.IsWindowsOs && d.IsBootloader) role = " [Windows OS + EFI Boot]";
                else if (d.IsWindowsOs) role = " [Windows OS]";
                else if (d.IsBootloader) role = " [EFI Bootloader]";

                sb.AppendLine(string.Format("  [Disk {0}] {1} ({2:F0} GB){3} -> {4} | {5} | {6}",
                    d.Index, d.Model, d.SizeGb, role, vols, d.InterfaceType, d.GetHealthBadge()));
                if (!string.IsNullOrEmpty(d.SerialNumber))
                {
                    sb.AppendLine(string.Format("    Hardware S/N: {0} | FW: {1}", d.SerialNumber, d.FirmwareRevision));
                }
                if (d.SmartHealthStatus != "Unknown")
                {
                    sb.AppendLine(string.Format("    SMART: {0} | Wear: {1} | Temp: {2} | Power-On: {3} | Uncorrected Errors: {4}",
                        d.SmartHealthStatus,
                        d.SmartWearPercent.HasValue ? d.SmartWearPercent.Value + "%" : "N/A",
                        d.SmartTemperatureCelsius.HasValue ? d.SmartTemperatureCelsius.Value + "\u00b0C" : "N/A",
                        d.SmartPowerOnHours.HasValue ? d.SmartPowerOnHours.Value + "h" : "N/A",
                        d.SmartReadErrorsUncorrected.HasValue ? d.SmartReadErrorsUncorrected.Value.ToString() : "N/A"));
                }
                else
                {
                    sb.AppendLine("    SMART: Unavailable (scan was not run as Administrator)");
                }
            }

            if (SplitBootDetected)
            {
                sb.AppendLine();
                sb.AppendLine("BOOT_ARCHITECTURE: BOOT CONFIGURATION NOTE (SPLIT-BOOT LAYOUT)");
                sb.AppendLine("  " + SplitBootDetails);
            }

            sb.AppendLine();
            sb.AppendLine("HARDWARE_INTEGRITY_AUDIT:");
            sb.AppendLine(string.Format("  CPU Thermal / Firmware Throttling (Event 37): {0}", 
                CpuThrottleCount > 0 ? string.Format("{0} events logged (Clock limited by thermals/firmware)", CpuThrottleCount) : "0 (Nominal)"));
            sb.AppendLine(string.Format("  Device Manager Hardware Faults: {0}", 
                PnpDeviceErrors.Count > 0 ? string.Format("{0} faulty devices ({1})", PnpDeviceErrors.Count, string.Join(", ", PnpDeviceErrors.ToArray())) : "0 (All devices nominal)"));
            sb.AppendLine(string.Format("  Windows Memory Diagnostic History: {0}", 
                !MemDiagRan ? "Not run" : (MemDiagFailed ? "HARDWARE FAULT DETECTED" : "Passed (0 errors)")));
            sb.AppendLine(string.Format("  Virtual Memory Exhaustion (Event 2004): {0}", 
                LowMemoryEvents > 0 ? string.Format("{0} low memory freeze events ({1})", LowMemoryEvents, LowMemorySummary) : "0 (Nominal)"));
            sb.AppendLine(string.Format("  Motherboard RTC Clock Drift (Dead CMOS Battery): {0}", 
                CmosClockDriftDetected ? "WARNING: Real-time clock reset detected (Dead CR2032 coin cell)" : "Normal (Synchronized)"));
            sb.AppendLine(string.Format("  Stopped Essential Automatic Services: {0}", 
                DeadAutoServices.Count > 0 ? string.Format("{0} ({1})", DeadAutoServices.Count, string.Join(", ", DeadAutoServices.ToArray())) : "0 (Nominal)"));

            sb.AppendLine();
            sb.AppendLine("SECURITY_FIRMWARE_CONFIG:");
            sb.AppendLine("  TPM Security: " + TpmStatus);
            sb.AppendLine("  UEFI Secure Boot: " + SecureBootStatus);
            sb.AppendLine("  OS Drive (C:) Encryption: " + BitLockerStatus);
            sb.AppendLine("  SSD TRIM Garbage Collection: " + (SsdTrimEnabled ? "Enabled (Healthy)" : "Disabled (SSD wear degradation)"));
            sb.AppendLine(string.Format("  Network Interface Packet Drops: {0} errors, {1} discards", NetworkPacketErrors, NetworkPacketDiscards));
            if (HasBattery && BatteryWearPercent >= 0)
            {
                sb.AppendLine(string.Format("  Battery Degradation: {0:F1}% wear ({1} charge cycles)", BatteryWearPercent, BatteryCycleCount >= 0 ? BatteryCycleCount.ToString() : "N/A"));
            }

            sb.AppendLine();
            sb.AppendLine("SYSTEM_EVENT_AUDIT_7D:");
            sb.AppendLine(string.Format("  Disk Bad Block Read Retries (Event ID 7/51/153): {0:N0}", BadBlockTotal));
            if (BadBlockTotal > 0)
            {
                sb.AppendLine("  Target Device: " + BadBlockTargetDevice);
                if (LatestRecordId > 0)
                {
                    sb.AppendLine(string.Format("  Verified Live Record: #{0} @ {1:yyyy-MM-dd HH:mm:ss}", LatestRecordId, LatestRecordTime));
                    sb.AppendLine("  Event Message: " + SampleEventMessage);
                }
            }
            sb.AppendLine(string.Format("  Unclean Freeze Reboots (Kernel-Power Event 41): {0}", KernelPowerEvents));
            if (!string.IsNullOrEmpty(KernelPowerStopCode))
            {
                sb.AppendLine("  Kernel-Power 41 BugcheckCode: " + KernelPowerStopCode);
            }
            sb.AppendLine(string.Format("  WHEA Hardware Errors (Event 18/19/47): {0} {1}", WheaCount, WheaSummary != "None detected" ? "(" + WheaSummary + ")" : ""));
            if (WheaCount > 0 && WheaLatestRecordId > 0)
            {
                sb.AppendLine(string.Format("  WHEA Latest Record: #{0} @ {1:yyyy-MM-dd HH:mm:ss}", WheaLatestRecordId, WheaLatestTime));
            }
            sb.AppendLine(string.Format("  BugCheck BSOD (Event 1001): {0} {1}", BugCheckCount, BugCheckSummary != "None detected" ? "(" + BugCheckSummary + ")" : ""));
            if (!string.IsNullOrEmpty(BugCheckStopCode))
            {
                sb.AppendLine("  Stop Code: " + BugCheckStopCode);
            }
            sb.AppendLine(string.Format("  Display Driver TDR (Event 4101): {0} {1}", DisplayTdrCount, DisplayTdrSummary != "None detected" ? "(" + DisplayTdrSummary + ")" : ""));
            sb.AppendLine("  Application Crashes (Event 1000 - Software Stability): " + SoftwareStability);
            sb.AppendLine("  MiniDump Crash Archive: " + MiniDumpSummary);
            sb.AppendLine();
            sb.AppendLine("WINDOWS_OS_VERIFICATION:");
            sb.AppendLine("  To independently cross-verify these exact records on this machine, run in PowerShell:");
            sb.AppendLine("  Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk'; Id=7} -MaxEvents 3 | Format-List");
            sb.AppendLine("  Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 3 | Format-List");
            sb.AppendLine("  Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 3 | Format-List");
            sb.AppendLine();
            sb.AppendLine("DIAGNOSIS_VERDICT:");
            sb.AppendLine("  " + OperationalStatusText);
            sb.AppendLine("  " + VerdictLabel + ".");
            sb.AppendLine("  ADVICE: " + VerdictAdvice);
            if (HasTier1HardwareFault)
            {
                if (WheaCount > 0) sb.AppendLine("  - WHEA: Uncorrectable CPU/memory/bus hardware errors logged.");
                if (MemDiagFailed) sb.AppendLine("  - RAM: Hardware memory fault confirmed by Windows Memory Diagnostic.");
                if (Disks.Exists(d => d.IsSsdDeath)) sb.AppendLine("  - Storage: SSD severe wear or predictive failure. Replace the drive.");
                if (KernelPowerStopCode != null && (KernelPowerStopCode.IndexOf("0x124", StringComparison.OrdinalIgnoreCase) >= 0 || KernelPowerStopCode.IndexOf("0x7A", StringComparison.OrdinalIgnoreCase) >= 0 || KernelPowerStopCode.IndexOf("0x1A", StringComparison.OrdinalIgnoreCase) >= 0))
                    sb.AppendLine("  - Power: Kernel-Power 41 bugcheck " + KernelPowerStopCode + " indicates hardware fault.");
            }
            else if (HasTier2Maintenance)
            {
                if (BadBlockTotal > 0) sb.AppendLine(string.Format("  - Storage: {0:N0} read retries logged. Run chkdsk /r and back up the affected partition.", BadBlockTotal));
                if (CpuThrottleCount > 0) sb.AppendLine(string.Format("  - CPU: Firmware/Thermal throttling detected ({0} events). Clean cooler or reapply thermal paste.", CpuThrottleCount));
                if (DisplayTdrCount > 0) sb.AppendLine("  - Display driver resets (TDR). Clean reinstall the GPU driver using DDU.");
                if (NtfsCorruptionEvents > 0) sb.AppendLine("  - File System: NTFS volume directory corruption logged. Run chkdsk.");
            }
            else
            {
                if (SplitBootDetected) sb.AppendLine("  - Boot: Split-boot layout note. Boot files on a secondary drive. Keep both drives connected.");
                if (XmpDisabledSuspected) sb.AppendLine("  - Memory: XMP/EXPO disabled. Enable in BIOS for a bandwidth boost (optional).");
                if (CmosClockDriftDetected) sb.AppendLine("  - Motherboard: RTC clock drift. Replace CR2032 coin cell.");
                if (!SplitBootDetected && !XmpDisabledSuspected && !CmosClockDriftDetected) sb.AppendLine("  SYSTEM NOMINAL: No hardware faults detected.");
            }
            sb.AppendLine("================================");
            return sb.ToString();
        }
    }

    public class MainWindow : Window
    {
        // Mockup 1:1 Palette
        private SolidColorBrush _bgShell = new SolidColorBrush(Color.FromRgb(18, 22, 31)); // #12161f
        private SolidColorBrush _bgCard = new SolidColorBrush(Color.FromRgb(22, 27, 34)); // #161b22
        private SolidColorBrush _bgSubtle = new SolidColorBrush(Color.FromRgb(33, 38, 45)); // #21262d
        private SolidColorBrush _borderLine = new SolidColorBrush(Color.FromRgb(33, 38, 45)); // #21262d (pcfix web subtle border)
        private SolidColorBrush _borderFaint = new SolidColorBrush(Color.FromArgb(40, 230, 237, 243));
        private SolidColorBrush _accent = new SolidColorBrush(Color.FromRgb(88, 166, 255)); // #58a6ff
        private SolidColorBrush _accentBtn = new SolidColorBrush(Color.FromRgb(26, 115, 232)); // #1a73e8
        private SolidColorBrush _accentBtnHover = new SolidColorBrush(Color.FromRgb(21, 87, 176)); // #1557b0
        private SolidColorBrush _textPrimary = new SolidColorBrush(Color.FromRgb(230, 237, 243)); // #e6edf3
        private SolidColorBrush _textSecondary = new SolidColorBrush(Color.FromRgb(139, 148, 158)); // #8b949e
        private SolidColorBrush _textMuted = new SolidColorBrush(Color.FromRgb(125, 135, 146)); // #7d8792
        private SolidColorBrush _colorOk = new SolidColorBrush(Color.FromRgb(63, 185, 80)); // #3fb950
        private SolidColorBrush _colorWarn = new SolidColorBrush(Color.FromRgb(210, 153, 34)); // #d29922
        private SolidColorBrush _colorCritical = new SolidColorBrush(Color.FromRgb(248, 81, 73)); // #f85149
        private SolidColorBrush _colorDegraded = new SolidColorBrush(Color.FromRgb(219, 109, 40)); // orange 45-64 tier

        // Theme dynamic brushes
        private bool _isDarkMode = true;
        private Border _themeThumb;
        private System.Windows.Shapes.Path _themeIcon;
        private SolidColorBrush _trustBadgeBg = new SolidColorBrush(Color.FromArgb(25, 63, 185, 80));
        private SolidColorBrush _trustBadgeBorder = new SolidColorBrush(Color.FromArgb(70, 63, 185, 80));
        private SolidColorBrush _chipIconBg = new SolidColorBrush(Color.FromArgb(35, 88, 166, 255));
        private SolidColorBrush _bgSubtleHover = new SolidColorBrush(Color.FromRgb(48, 54, 61));

        // State & Controls
        private HardwareReport _latestReport;
        private Border _rootBorder;
        private Grid _viewIdle;
        private Grid _viewScanning;
        private Grid _viewResults;
        private Grid _viewPrivacy;
        private ProgressBar _scanProgressBar;
        private TextBlock _scanStatusText;
        private TextBlock _scanPctText;
        private TextBox _logTerminal;
        private Border _btnTabScanBorder;
        private TextBlock _btnTabScanText;
        private Border _btnTabPrivacyBorder;
        private TextBlock _btnTabPrivacyText;
        private Border _btnCopyReport;
        private TextBlock _btnCopyText;
        private System.Windows.Shapes.Path _btnCopyIcon;
        private bool _isCopiedState = false;
        private static readonly TimeSpan _wmiTimeout = TimeSpan.FromSeconds(3.5);
        private static readonly TimeSpan _scanWatchdog = TimeSpan.FromSeconds(120);
        private bool _isScanning = false;
        private DispatcherTimer _copyResetTimer;

        // 3-Tier Matrix Controls (Matching Mockup)
        private TextBlock _cpuTitle;
        private TextBlock _cpuSub;
        private TextBlock _gpuTitle;
        private TextBlock _gpuSub;
        private TextBlock _ramTitle;
        private TextBlock _ramSub;
        private TextBlock _storageTitle;
        private TextBlock _storageSub;

        // Alert Box Controls
        private Border _alertCard;
        private Border _alertIconBox;
        private TextBlock _alertIconText;
        private TextBlock _alertHeading;
        private TextBlock _alertDesc;
        private Border _sysInfoCard;
        private TextBlock _sysInfoText;
        private TextBlock _osInfoText;
        private Border _scoreBadge;
        private TextBlock _scoreBadgeText;
        private StackPanel _disksContainer;
        private StackPanel _eventMetricsPanel;
        private StackPanel _proofContainer;
        private TextBox _rawPayloadPreview;
        private StackPanel _qrContainer;
        private Border _btnMemTest;
        private TextBlock _btnMemTestText;

        public MainWindow()
        {
            Title = "pcfix diagnostic scanner";
            Width = 620;
            SizeToContent = SizeToContent.Height;
            MaxHeight = 720;
            MinHeight = 0;
            WindowStartupLocation = WindowStartupLocation.CenterScreen;
            WindowStyle = WindowStyle.None;
            AllowsTransparency = true;
            Background = Brushes.Transparent;
            FontFamily = new FontFamily("Inter, -apple-system, Segoe UI, sans-serif");

            _latestReport = new HardwareReport();
            BuildUi();
        }

        private void BuildUi()
        {
            _rootBorder = new Border
            {
                Background = _bgShell,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(24),
                ClipToBounds = true,
                Effect = new DropShadowEffect
                {
                    Color = Colors.Black,
                    Opacity = 0.65,
                    BlurRadius = 30,
                    ShadowDepth = 6
                }
            };

            Grid mainGrid = new Grid { Background = _bgShell };
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 0: Title Bar
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 1: Navigation
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) }); // 2: Content
            mainGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); // 3: Status Footer

            // Row 0: Custom Title Bar
            mainGrid.Children.Add(CreateTitleBar());
            Grid.SetRow((UIElement)mainGrid.Children[mainGrid.Children.Count - 1], 0);

            // Row 1: Tab Navigation & Trust Badge
            mainGrid.Children.Add(CreateNavigationRow());
            Grid.SetRow((UIElement)mainGrid.Children[mainGrid.Children.Count - 1], 1);

            // Row 2: Content Container with Scroll
            ScrollViewer scroll = new ScrollViewer
            {
                Background = _bgShell,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
                Padding = new Thickness(20, 16, 20, 16)
            };

            StackPanel contentPanel = new StackPanel { Background = _bgShell };
            BuildIdleView();
            BuildScanningView();
            BuildResultsView();
            BuildPrivacyView();

            contentPanel.Children.Add(_viewIdle);
            contentPanel.Children.Add(_viewScanning);
            contentPanel.Children.Add(_viewResults);
            contentPanel.Children.Add(_viewPrivacy);
            scroll.Content = contentPanel;

            mainGrid.Children.Add(scroll);
            Grid.SetRow(scroll, 2);

            // Row 3: Status Footer
            mainGrid.Children.Add(CreateStatusFooter());
            Grid.SetRow((UIElement)mainGrid.Children[mainGrid.Children.Count - 1], 3);

            _rootBorder.Child = mainGrid;
            Content = _rootBorder;
        }

        private UIElement CreateTitleBar()
        {
            Border bar = new Border
            {
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 10, 16, 10)
            };
            bar.MouseLeftButtonDown += (s, e) => { if (e.ButtonState == MouseButtonState.Pressed) DragMove(); };

            Grid grid = new Grid();
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Brand Section
            StackPanel brand = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            
            // Logo Box (32x32 Squircle with exact PCFix geometric logo)
            Border logoBox = new Border
            {
                Width = 32,
                Height = 32,
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Margin = new Thickness(0, 0, 10, 0)
            };
            
            // Exact pcfix SVG aperture polygon with EvenOdd rule (F1)
            System.Windows.Shapes.Path logoIcon = new System.Windows.Shapes.Path
            {
                Fill = _accent,
                Width = 16,
                Height = 16,
                Stretch = Stretch.Uniform,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Data = Geometry.Parse("F1 M 538 481 L 477 446 L 443 466 L 389 570 L 539 483 Z M 10 483 L 145 562 L 228 537 L 73 446 L 16 478 Z M 360 418 L 219 501 L 220 503 L 275 535 L 305 517 L 311 512 Z M 0 311 L 0 467 L 63 431 L 64 404 Z M 303 209 L 394 394 L 319 539 L 276 564 L 247 550 L 166 574 L 275 637 L 360 587 L 462 391 L 386 259 Z M 549 168 L 486 204 L 485 231 L 549 324 Z M 0 168 L 0 279 L 106 434 L 198 490 L 254 458 L 149 394 L 64 259 L 64 205 Z M 294 179 L 402 244 L 485 376 L 486 431 L 549 467 L 549 356 L 445 204 L 349 147 Z M 329 135 L 276 104 L 268 107 L 241 123 L 192 216 L 321 141 Z M 159 66 L 10 153 L 73 190 L 101 174 L 106 170 Z M 296 85 L 476 190 L 539 153 L 381 61 Z M 266 3 L 187 50 L 87 245 L 164 378 L 248 428 L 156 241 Z M 360 49 L 278 0 L 276 1 L 233 97 L 276 72 Z")
            };
            logoBox.Child = logoIcon;
            brand.Children.Add(logoBox);

            StackPanel titleStack = new StackPanel { VerticalAlignment = VerticalAlignment.Center };
            StackPanel nameRow = new StackPanel { Orientation = Orientation.Horizontal };
            TextBlock brandName = new TextBlock
            {
                Text = "pcfix",
                FontWeight = FontWeights.ExtraBold,
                FontSize = 15,
                Foreground = _textPrimary,
                Margin = new Thickness(0, 0, 5, 0)
            };
            TextBlock subBadge = new TextBlock
            {
                Text = "diagnostic scanner",
                FontWeight = FontWeights.SemiBold,
                FontSize = 10,
                Foreground = _textSecondary,
                VerticalAlignment = VerticalAlignment.Center
            };
            nameRow.Children.Add(brandName);
            nameRow.Children.Add(subBadge);

            TextBlock authorTag = new TextBlock
            {
                Text = "by shin",
                FontSize = 10,
                FontWeight = FontWeights.SemiBold,
                Foreground = _textMuted
            };

            titleStack.Children.Add(nameRow);
            titleStack.Children.Add(authorTag);
            brand.Children.Add(titleStack);

            Border verPill = new Border
            {
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(7, 2, 7, 2),
                Margin = new Thickness(10, 0, 0, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            verPill.Child = new TextBlock
            {
                Text = "v1.0.4",
                FontSize = 10.5,
                FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                Foreground = _textSecondary,
                FontWeight = FontWeights.Medium
            };
            brand.Children.Add(verPill);

            grid.Children.Add(brand);
            Grid.SetColumn(brand, 0);

            // Right Actions: Theme Toggle Pill + Window Controls (Matching Mockup exactly)
            StackPanel actions = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };

            // Theme Switcher Pill (Matching Mockup with sliding circular thumb and moon vector icon)
            Border themePill = new Border
            {
                Width = 44,
                Height = 24,
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(2),
                Margin = new Thickness(0, 0, 10, 0),
                Cursor = Cursors.Hand
            };
            _themeThumb = new Border
            {
                Width = 18,
                Height = 18,
                Background = _bgCard,
                CornerRadius = new CornerRadius(9),
                HorizontalAlignment = HorizontalAlignment.Right,
                Cursor = Cursors.Hand
            };
            _themeIcon = new System.Windows.Shapes.Path
            {
                Stroke = _accent,
                StrokeThickness = 1.6,
                Fill = Brushes.Transparent,
                Width = 11,
                Height = 11,
                Stretch = Stretch.Uniform,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Data = Geometry.Parse("M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z")
            };
            _themeThumb.Child = _themeIcon;
            themePill.Child = _themeThumb;
            themePill.PreviewMouseLeftButtonDown += (s, e) =>
            {
                e.Handled = true;
                ToggleTheme();
            };
            actions.Children.Add(themePill);

            // Borderless Native Window Buttons (Matching Mockup: ─, □, ✕)
            actions.Children.Add(CreateWinButton("─", (s, e) => { e.Handled = true; WindowState = WindowState.Minimized; }, false));
            actions.Children.Add(CreateWinButton("□", (s, e) => { e.Handled = true; WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized; }, false));
            actions.Children.Add(CreateWinButton("✕", (s, e) => { e.Handled = true; Close(); }, true));

            grid.Children.Add(actions);
            Grid.SetColumn(actions, 2);

            bar.Child = grid;
            return bar;
        }

        private void ToggleTheme()
        {
            _isDarkMode = !_isDarkMode;
            if (_isDarkMode)
            {
                _bgShell.Color = Color.FromRgb(18, 22, 31); // #12161f
                _bgCard.Color = Color.FromRgb(22, 27, 34); // #161b22
                _bgSubtle.Color = Color.FromRgb(33, 38, 45); // #21262d
                _borderLine.Color = Color.FromRgb(33, 38, 45); // #21262d
                _borderFaint.Color = Color.FromArgb(40, 230, 237, 243);
                _textPrimary.Color = Color.FromRgb(230, 237, 243); // #e6edf3
                _textSecondary.Color = Color.FromRgb(139, 148, 158); // #8b949e
                _textMuted.Color = Color.FromRgb(125, 135, 146); // #7d8792
                _accent.Color = Color.FromRgb(88, 166, 255); // #58a6ff
                _colorOk.Color = Color.FromRgb(63, 185, 80); // #3fb950
                _colorWarn.Color = Color.FromRgb(210, 153, 34);
                _colorCritical.Color = Color.FromRgb(248, 81, 73);

                _trustBadgeBg.Color = Color.FromArgb(25, 63, 185, 80);
                _trustBadgeBorder.Color = Color.FromArgb(70, 63, 185, 80);
                _chipIconBg.Color = Color.FromArgb(35, 88, 166, 255);
                _bgSubtleHover.Color = Color.FromRgb(48, 54, 61);

                DropShadowEffect shadow = _rootBorder != null ? _rootBorder.Effect as DropShadowEffect : null;
                if (shadow != null)
                {
                    shadow.Opacity = 0.65;
                }

                _themeThumb.HorizontalAlignment = HorizontalAlignment.Right;
                _themeThumb.Background = _bgCard;
                _themeIcon.Stroke = _accent;
                _themeIcon.Data = Geometry.Parse("M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z");
            }
            else
            {
                _bgShell.Color = Color.FromRgb(246, 248, 250); // #f6f8fa
                _bgCard.Color = Color.FromRgb(255, 255, 255); // #ffffff
                _bgSubtle.Color = Color.FromRgb(234, 238, 242); // #eaeef2
                _borderLine.Color = Color.FromRgb(209, 217, 224); // #d1d9e0
                _borderFaint.Color = Color.FromArgb(30, 27, 31, 36);
                _textPrimary.Color = Color.FromRgb(28, 33, 40); // #1c2128
                _textSecondary.Color = Color.FromRgb(87, 96, 106); // #57606a
                _textMuted.Color = Color.FromRgb(107, 114, 128); // #6b7280
                _accent.Color = Color.FromRgb(26, 115, 232); // #1a73e8
                _colorOk.Color = Color.FromRgb(24, 128, 56); // #188038
                _colorWarn.Color = Color.FromRgb(176, 112, 10);
                _colorCritical.Color = Color.FromRgb(207, 34, 46);

                _trustBadgeBg.Color = Color.FromArgb(25, 24, 128, 56);
                _trustBadgeBorder.Color = Color.FromArgb(70, 24, 128, 56);
                _chipIconBg.Color = Color.FromArgb(25, 26, 115, 232);
                _bgSubtleHover.Color = Color.FromRgb(209, 217, 224);

                DropShadowEffect shadow = _rootBorder != null ? _rootBorder.Effect as DropShadowEffect : null;
                if (shadow != null)
                {
                    shadow.Opacity = 0.18;
                }

                _themeThumb.HorizontalAlignment = HorizontalAlignment.Left;
                _themeThumb.Background = Brushes.White;
                _themeIcon.Stroke = _accent;
                _themeIcon.Data = Geometry.Parse("M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z");
            }
        }

        private Border CreateWinButton(string symbol, MouseButtonEventHandler handler, bool isClose)
        {
            Border btn = new Border
            {
                Width = 24,
                Height = 24,
                Background = Brushes.Transparent,
                CornerRadius = new CornerRadius(6),
                Cursor = Cursors.Hand,
                Margin = new Thickness(3, 0, 0, 0)
            };

            TextBlock tb = new TextBlock
            {
                Text = symbol,
                FontSize = 11,
                FontWeight = FontWeights.Normal,
                Foreground = _textMuted,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            btn.Child = tb;

            btn.MouseEnter += (s, e) =>
            {
                if (isClose)
                {
                    btn.Background = new SolidColorBrush(Color.FromArgb(40, 248, 81, 73));
                    tb.Foreground = _colorCritical;
                }
                else
                {
                    btn.Background = _bgSubtle;
                    tb.Foreground = _textPrimary;
                }
            };
            btn.MouseLeave += (s, e) =>
            {
                btn.Background = Brushes.Transparent;
                tb.Foreground = _textMuted;
            };

            btn.PreviewMouseLeftButtonDown += handler;
            return btn;
        }

        private UIElement CreateNavigationRow()
        {
            Border navBorder = new Border
            {
                Background = _bgShell,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(0, 0, 0, 1),
                Padding = new Thickness(16, 7, 16, 7)
            };

            Grid navGrid = new Grid();
            navGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            navGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            navGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            // Pill Tabs Group Container (Matching Mockup)
            Border pillGroup = new Border
            {
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(11),
                Padding = new Thickness(2)
            };
            StackPanel pillStack = new StackPanel { Orientation = Orientation.Horizontal };

            // Tab 1: Scan & Diagnose (Active)
            _btnTabScanBorder = new Border
            {
                Background = _bgCard,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(14, 5, 14, 5),
                Cursor = Cursors.Hand
            };
            _btnTabScanText = new TextBlock
            {
                Text = "Scan & Diagnose",
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = _accent
            };
            _btnTabScanBorder.Child = _btnTabScanText;
            _btnTabScanBorder.MouseLeftButtonDown += (s, e) => SwitchTab(true);

            // Tab 2: Privacy & Transparency (Inactive)
            _btnTabPrivacyBorder = new Border
            {
                Background = Brushes.Transparent,
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(14, 5, 14, 5),
                Cursor = Cursors.Hand
            };
            _btnTabPrivacyText = new TextBlock
            {
                Text = "Privacy & Transparency",
                FontSize = 11.5,
                FontWeight = FontWeights.Medium,
                Foreground = _textSecondary
            };
            _btnTabPrivacyBorder.Child = _btnTabPrivacyText;
            _btnTabPrivacyBorder.MouseLeftButtonDown += (s, e) => SwitchTab(false);

            pillStack.Children.Add(_btnTabScanBorder);
            pillStack.Children.Add(_btnTabPrivacyBorder);
            pillGroup.Child = pillStack;

            navGrid.Children.Add(pillGroup);
            Grid.SetColumn(pillGroup, 0);

            // Trust Pill (LOCAL ONLY)
            Border trustBadge = new Border
            {
                Background = _trustBadgeBg,
                BorderBrush = _trustBadgeBorder,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(12, 3, 12, 3),
                VerticalAlignment = VerticalAlignment.Center
            };
            trustBadge.Child = new TextBlock
            {
                Text = "LOCAL ONLY",
                FontSize = 10,
                FontWeight = FontWeights.Bold,
                Foreground = _colorOk
            };
            navGrid.Children.Add(trustBadge);
            Grid.SetColumn(trustBadge, 2);

            navBorder.Child = navGrid;
            return navBorder;
        }

        private void BuildIdleView()
        {
            _viewIdle = new Grid { Visibility = Visibility.Visible };
            StackPanel stack = new StackPanel();

            // Main Diagnostic Card (Matching Mockup with 16px radius, padding 18)
            Border card = new Border
            {
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(16),
                Padding = new Thickness(18),
                Margin = new Thickness(0, 0, 0, 14)
            };

            StackPanel cardStack = new StackPanel();

            // Card Header
            Grid headerGrid = new Grid();
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            headerGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            StackPanel headLeft = new StackPanel { Orientation = Orientation.Horizontal, VerticalAlignment = VerticalAlignment.Center };
            
            // Microchip Icon Box (Matching Mockup)
            Border iconBox = new Border
            {
                Width = 30,
                Height = 30,
                Background = _chipIconBg,
                CornerRadius = new CornerRadius(10),
                Margin = new Thickness(0, 0, 10, 0)
            };
            System.Windows.Shapes.Path chipIcon = new System.Windows.Shapes.Path
            {
                Stroke = _accent,
                StrokeThickness = 1.5,
                Width = 16,
                Height = 16,
                Stretch = Stretch.Uniform,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center,
                Data = Geometry.Parse("M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z")
            };
            iconBox.Child = chipIcon;
            headLeft.Children.Add(iconBox);

            TextBlock cardTitle = new TextBlock
            {
                Text = "System Telemetry & Hardware Scanner",
                FontSize = 13.5,
                FontWeight = FontWeights.Bold,
                Foreground = _textPrimary,
                VerticalAlignment = VerticalAlignment.Center
            };
            headLeft.Children.Add(cardTitle);
            headerGrid.Children.Add(headLeft);
            Grid.SetColumn(headLeft, 0);

            Border badge = new Border
            {
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(9, 3, 9, 3),
                VerticalAlignment = VerticalAlignment.Center
            };
            badge.Child = new TextBlock
            {
                Text = "Quick Scan (~15s)",
                FontSize = 10.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = _textSecondary
            };
            headerGrid.Children.Add(badge);
            Grid.SetColumn(badge, 1);

            cardStack.Children.Add(headerGrid);

            // Description
            TextBlock desc = new TextBlock
            {
                Text = "Performs a read-only hardware scan using local Windows CIM interfaces. Collects CPU clocks, RAM capacity, GPU driver version, NVMe S.M.A.R.T. health, and recent MiniDump crash headers.",
                FontSize = 12.5,
                Foreground = _textSecondary,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 18,
                Margin = new Thickness(0, 10, 0, 14)
            };
            cardStack.Children.Add(desc);

            // 4 Checks (2-column responsive grid matching mockup)
            Border checksBorder = new Border
            {
                BorderBrush = _borderFaint,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(0, 10, 0, 0)
            };
            Grid checksGrid = new Grid();
            checksGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            checksGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            checksGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            checksGrid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            UIElement c1 = CreateCheckItem("Zero installation / Portable single file");
            UIElement c2 = CreateCheckItem("No user files or passwords accessed");
            UIElement c3 = CreateCheckItem("Zero background services left behind");
            UIElement c4 = CreateCheckItem("Zero telemetry uploaded to cloud");

            Grid.SetRow(c1, 0); Grid.SetColumn(c1, 0);
            Grid.SetRow(c2, 0); Grid.SetColumn(c2, 1);
            Grid.SetRow(c3, 1); Grid.SetColumn(c3, 0);
            Grid.SetRow(c4, 1); Grid.SetColumn(c4, 1);

            checksGrid.Children.Add(c1);
            checksGrid.Children.Add(c2);
            checksGrid.Children.Add(c3);
            checksGrid.Children.Add(c4);

            checksBorder.Child = checksGrid;
            cardStack.Children.Add(checksBorder);

            card.Child = cardStack;
            stack.Children.Add(card);

            // Run Scan Button (Matching Mockup exactly: rounded-xl, 48px, #1a73e8, glow)
            Border btnScan = new Border
            {
                Height = 48,
                Background = _accentBtn,
                CornerRadius = new CornerRadius(12),
                Cursor = Cursors.Hand,
                Effect = new DropShadowEffect
                {
                    Color = Color.FromRgb(26, 115, 232),
                    Opacity = 0.35,
                    BlurRadius = 14,
                    ShadowDepth = 2
                }
            };
            btnScan.MouseEnter += (s, e) => btnScan.Background = _accentBtnHover;
            btnScan.MouseLeave += (s, e) => btnScan.Background = _accentBtn;
            btnScan.MouseLeftButtonDown += (s, e) => StartScan();

            StackPanel btnContent = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            
            // Clean outline lightning bolt icon (matching mockup SVG stroke-2)
            System.Windows.Shapes.Path btnIcon = new System.Windows.Shapes.Path
            {
                Stroke = Brushes.White,
                StrokeThickness = 2,
                Fill = Brushes.Transparent,
                Width = 16,
                Height = 16,
                Stretch = Stretch.Uniform,
                Data = Geometry.Parse("M13 10V3L4 14h7v7l9-11h-7z"),
                Margin = new Thickness(0, 0, 8, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            TextBlock btnText = new TextBlock
            {
                Text = "Run System Diagnostic Scan",
                FontSize = 13,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center
            };
            btnContent.Children.Add(btnIcon);
            btnContent.Children.Add(btnText);
            btnScan.Child = btnContent;

            stack.Children.Add(btnScan);
            _viewIdle.Children.Add(stack);
        }

        private UIElement CreateCheckItem(string label)
        {
            StackPanel p = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 3, 0, 3) };
            TextBlock check = new TextBlock
            {
                Text = "✓ ",
                FontWeight = FontWeights.Bold,
                Foreground = _colorOk,
                FontSize = 12,
                Margin = new Thickness(0, 0, 6, 0)
            };
            TextBlock txt = new TextBlock
            {
                Text = label,
                FontSize = 12,
                Foreground = _textPrimary
            };
            p.Children.Add(check);
            p.Children.Add(txt);
            return p;
        }

        private void BuildScanningView()
        {
            _viewScanning = new Grid { Visibility = Visibility.Collapsed };
            StackPanel stack = new StackPanel();

            Grid progRow = new Grid { Margin = new Thickness(0, 0, 0, 10) };
            progRow.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            progRow.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            _scanStatusText = new TextBlock
            {
                Text = "Scanning Win32_Processor...",
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                Foreground = _textPrimary
            };
            _scanPctText = new TextBlock
            {
                Text = "0%",
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                Foreground = _accent,
                FontFamily = new FontFamily("Consolas, monospace")
            };

            progRow.Children.Add(_scanStatusText);
            Grid.SetColumn(_scanStatusText, 0);
            progRow.Children.Add(_scanPctText);
            Grid.SetColumn(_scanPctText, 1);
            stack.Children.Add(progRow);

            Border progTrack = new Border
            {
                Height = 8,
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(4),
                Margin = new Thickness(0, 0, 0, 14)
            };
            _scanProgressBar = new ProgressBar
            {
                Height = 8,
                Minimum = 0,
                Maximum = 100,
                Value = 0,
                Foreground = _accent,
                Background = Brushes.Transparent,
                BorderThickness = new Thickness(0)
            };
            progTrack.Child = _scanProgressBar;
            stack.Children.Add(progTrack);

            Border terminalBorder = new Border
            {
                Background = new SolidColorBrush(Color.FromRgb(3, 7, 18)),
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Height = 220,
                Padding = new Thickness(14)
            };

            _logTerminal = new TextBox
            {
                Background = Brushes.Transparent,
                Foreground = new SolidColorBrush(Color.FromRgb(203, 213, 225)),
                BorderThickness = new Thickness(0),
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
                FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                FontSize = 10.5
            };
            terminalBorder.Child = _logTerminal;
            stack.Children.Add(terminalBorder);

            _viewScanning.Children.Add(stack);
        }

        private void BuildResultsView()
        {
            _viewResults = new Grid { Visibility = Visibility.Collapsed };
            StackPanel stack = new StackPanel();

            _alertCard = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(20, 210, 153, 34)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(60, 210, 153, 34)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(14),
                Margin = new Thickness(0, 0, 0, 14)
            };

            Grid alertGrid = new Grid();
            alertGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
            alertGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            _alertIconBox = new Border
            {
                Width = 24,
                Height = 24,
                Background = new SolidColorBrush(Color.FromArgb(50, 210, 153, 34)),
                CornerRadius = new CornerRadius(7),
                Margin = new Thickness(0, 0, 10, 0),
                VerticalAlignment = VerticalAlignment.Top
            };
            _alertIconText = new TextBlock
            {
                Text = "!",
                FontSize = 12,
                FontWeight = FontWeights.Bold,
                Foreground = _colorWarn,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            _alertIconBox.Child = _alertIconText;
            alertGrid.Children.Add(_alertIconBox);
            Grid.SetColumn(_alertIconBox, 0);

            StackPanel alertStack = new StackPanel();
            _alertHeading = new TextBlock
            {
                Text = "Diagnostic Analysis",
                FontSize = 13,
                FontWeight = FontWeights.Bold,
                Foreground = _colorWarn,
                Margin = new Thickness(0, 0, 0, 4)
            };
            _alertDesc = new TextBlock
            {
                Text = "Analyzing hardware telemetry...",
                FontSize = 11.5,
                Foreground = _textSecondary,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 16
            };
            alertStack.Children.Add(_alertHeading);
            alertStack.Children.Add(_alertDesc);
            alertGrid.Children.Add(alertStack);
            Grid.SetColumn(alertStack, 1);

            _alertCard.Child = alertGrid;
            stack.Children.Add(_alertCard);

            // Phase 3: pcfix Score Badge (inserted between alert card and system info card)
            _scoreBadge = new Border
            {
                Height = 38,
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(14, 0, 14, 0),
                Margin = new Thickness(0, 0, 0, 12),
                HorizontalAlignment = HorizontalAlignment.Left
            };
            _scoreBadgeText = new TextBlock
            {
                FontSize = 13,
                FontWeight = FontWeights.Bold,
                VerticalAlignment = VerticalAlignment.Center
            };
            _scoreBadge.Child = _scoreBadgeText;
            stack.Children.Add(_scoreBadge);


            _sysInfoCard = new Border
            {
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(14, 9, 14, 9),
                Margin = new Thickness(0, 0, 0, 12)
            };
            StackPanel sysStack = new StackPanel();
            _sysInfoText = new TextBlock
            {
                Text = "Motherboard & Firmware",
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = _textPrimary
            };
            _osInfoText = new TextBlock
            {
                Text = "Operating System",
                FontSize = 10.5,
                Foreground = _textSecondary,
                Margin = new Thickness(0, 2, 0, 0)
            };
            sysStack.Children.Add(_sysInfoText);
            sysStack.Children.Add(_osInfoText);
            _sysInfoCard.Child = sysStack;
            stack.Children.Add(_sysInfoCard);

            Grid matrix = new Grid { Margin = new Thickness(0, 0, 0, 14) };
            matrix.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            matrix.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            matrix.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            matrix.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

            _cpuTitle = new TextBlock { Text = "Loading...", FontWeight = FontWeights.Bold, FontSize = 12, Foreground = _textPrimary, TextTrimming = TextTrimming.CharacterEllipsis };
            _cpuSub = new TextBlock { Text = "Querying...", FontWeight = FontWeights.Medium, FontSize = 10.5, Foreground = _colorOk, Margin = new Thickness(0, 2, 0, 0) };

            _gpuTitle = new TextBlock { Text = "Loading...", FontWeight = FontWeights.Bold, FontSize = 12, Foreground = _textPrimary, TextTrimming = TextTrimming.CharacterEllipsis };
            _gpuSub = new TextBlock { Text = "Querying...", FontWeight = FontWeights.Medium, FontSize = 10.5, Foreground = _textSecondary, Margin = new Thickness(0, 2, 0, 0) };

            _ramTitle = new TextBlock { Text = "Loading...", FontWeight = FontWeights.Bold, FontSize = 12, Foreground = _textPrimary, TextTrimming = TextTrimming.CharacterEllipsis };
            _ramSub = new TextBlock { Text = "Querying...", FontWeight = FontWeights.Medium, FontSize = 10.5, Foreground = _colorOk, Margin = new Thickness(0, 2, 0, 0) };

            _storageTitle = new TextBlock { Text = "Loading...", FontWeight = FontWeights.Bold, FontSize = 12, Foreground = _textPrimary, TextTrimming = TextTrimming.CharacterEllipsis };
            _storageSub = new TextBlock { Text = "Querying...", FontWeight = FontWeights.Medium, FontSize = 10.5, Foreground = _colorOk, Margin = new Thickness(0, 2, 0, 0) };

            matrix.Children.Add(CreateMatrixCard("CPU / PROCESSOR", _cpuTitle, _cpuSub, 0, 0));
            matrix.Children.Add(CreateMatrixCard("GPU / GRAPHICS", _gpuTitle, _gpuSub, 1, 0));
            matrix.Children.Add(CreateMatrixCard("SYSTEM MEMORY", _ramTitle, _ramSub, 0, 1));
            matrix.Children.Add(CreateMatrixCard("STORAGE HEALTH", _storageTitle, _storageSub, 1, 1));

            stack.Children.Add(matrix);

            TextBlock disksHeader = new TextBlock
            {
                Text = "PHYSICAL STORAGE & PARTITION AUDIT",
                FontSize = 10.5,
                FontWeight = FontWeights.Bold,
                Foreground = _textMuted,
                Margin = new Thickness(2, 0, 0, 6)
            };
            stack.Children.Add(disksHeader);

            _disksContainer = new StackPanel { Margin = new Thickness(0, 0, 0, 14) };
            stack.Children.Add(_disksContainer);

            TextBlock eventHeader = new TextBlock
            {
                Text = "WINDOWS EVENT LOG HARDWARE AUDIT (7 DAYS)",
                FontSize = 10.5,
                FontWeight = FontWeights.Bold,
                Foreground = _textMuted,
                Margin = new Thickness(2, 0, 0, 6)
            };
            stack.Children.Add(eventHeader);

            _eventMetricsPanel = new StackPanel { Margin = new Thickness(0, 0, 0, 14) };
            stack.Children.Add(_eventMetricsPanel);

            TextBlock proofHeader = new TextBlock
            {
                Text = "WINDOWS KERNEL & EVENT LOG VERIFICATION PROOF",
                FontSize = 10.5,
                FontWeight = FontWeights.Bold,
                Foreground = _textMuted,
                Margin = new Thickness(2, 0, 0, 6)
            };
            stack.Children.Add(proofHeader);

            _proofContainer = new StackPanel { Margin = new Thickness(0, 0, 0, 14) };
            stack.Children.Add(_proofContainer);

            // Upgrade 3: QR handoff card. Rendered in PopulateResults after the scan.
            _qrContainer = new StackPanel { Margin = new Thickness(0, 0, 0, 14) };
            stack.Children.Add(_qrContainer);

            // Upgrade 5: memory diagnostic trigger (visible only when MemDiag has never run).
            _btnMemTest = new Border
            {
                Height = 46,
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(11),
                Cursor = Cursors.Hand,
                Margin = new Thickness(0, 0, 0, 12)
            };
            _btnMemTestText = new TextBlock
            {
                Text = "Schedule Memory Diagnostic on Next Reboot",
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Foreground = _colorWarn,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            };
            _btnMemTest.Child = _btnMemTestText;
            _btnMemTest.MouseEnter += (s, e) => _btnMemTest.Background = _bgSubtleHover;
            _btnMemTest.MouseLeave += (s, e) => _btnMemTest.Background = _bgSubtle;
            _btnMemTest.MouseLeftButtonDown += (s, e) => ScheduleMemoryDiagnostic();
            _btnMemTest.Visibility = Visibility.Collapsed;
            stack.Children.Add(_btnMemTest);

            Grid btnGrid = new Grid { Margin = new Thickness(0, 0, 0, 12) };
            btnGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2, GridUnitType.Star) });
            btnGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            btnGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            _btnCopyReport = new Border
            {
                Height = 46,
                Background = _accentBtn,
                CornerRadius = new CornerRadius(11),
                Cursor = Cursors.Hand,
                Margin = new Thickness(0, 0, 6, 0)
            };
            _btnCopyReport.MouseEnter += (s, e) => { if (!_isCopiedState) _btnCopyReport.Background = _accentBtnHover; };
            _btnCopyReport.MouseLeave += (s, e) => { if (!_isCopiedState) _btnCopyReport.Background = _accentBtn; };
            _btnCopyReport.MouseLeftButtonDown += (s, e) => CopyReportToClipboard();

            StackPanel copyStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            _btnCopyIcon = new System.Windows.Shapes.Path
            {
                Stroke = Brushes.White,
                StrokeThickness = 1.6,
                Fill = Brushes.Transparent,
                Width = 14,
                Height = 14,
                Stretch = Stretch.Uniform,
                Data = Geometry.Parse("M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3"),
                Margin = new Thickness(0, 0, 7, 0)
            };
            _btnCopyText = new TextBlock
            {
                Text = "Copy Report",
                FontSize = 12,
                FontWeight = FontWeights.SemiBold,
                Foreground = Brushes.White,
                VerticalAlignment = VerticalAlignment.Center
            };
            copyStack.Children.Add(_btnCopyIcon);
            copyStack.Children.Add(_btnCopyText);
            _btnCopyReport.Child = copyStack;
            btnGrid.Children.Add(_btnCopyReport);
            Grid.SetColumn(_btnCopyReport, 0);

            Border btnOpenAi = new Border
            {
                Height = 46,
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(11),
                Cursor = Cursors.Hand,
                Margin = new Thickness(0, 0, 6, 0)
            };
            btnOpenAi.MouseEnter += (s, e) => btnOpenAi.Background = _bgSubtleHover;
            btnOpenAi.MouseLeave += (s, e) => btnOpenAi.Background = _bgSubtle;
            btnOpenAi.MouseLeftButtonDown += (s, e) => OpenWebAi();

            StackPanel aiStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            System.Windows.Shapes.Path aiIcon = new System.Windows.Shapes.Path
            {
                Stroke = _textPrimary,
                StrokeThickness = 1.6,
                Fill = Brushes.Transparent,
                Width = 13,
                Height = 13,
                Stretch = Stretch.Uniform,
                Data = Geometry.Parse("M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14"),
                Margin = new Thickness(0, 0, 6, 0)
            };
            TextBlock aiText = new TextBlock
            {
                Text = "Open Web AI",
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = _textPrimary,
                VerticalAlignment = VerticalAlignment.Center
            };
            aiStack.Children.Add(aiIcon);
            aiStack.Children.Add(aiText);
            btnOpenAi.Child = aiStack;
            btnGrid.Children.Add(btnOpenAi);
            Grid.SetColumn(btnOpenAi, 1);

            Border btnRescan = new Border
            {
                Height = 46,
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(11),
                Cursor = Cursors.Hand
            };
            btnRescan.MouseEnter += (s, e) => btnRescan.Background = _bgSubtleHover;
            btnRescan.MouseLeave += (s, e) => btnRescan.Background = _bgSubtle;
            btnRescan.MouseLeftButtonDown += (s, e) => StartScan();

            StackPanel rescanStack = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Center };
            System.Windows.Shapes.Path rescanIcon = new System.Windows.Shapes.Path
            {
                Stroke = _textPrimary,
                StrokeThickness = 1.6,
                Fill = Brushes.Transparent,
                Width = 13,
                Height = 13,
                Stretch = Stretch.Uniform,
                Data = Geometry.Parse("M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"),
                Margin = new Thickness(0, 0, 6, 0)
            };
            TextBlock rescanText = new TextBlock
            {
                Text = "Re-Scan",
                FontSize = 11.5,
                FontWeight = FontWeights.SemiBold,
                Foreground = _textPrimary,
                VerticalAlignment = VerticalAlignment.Center
            };
            rescanStack.Children.Add(rescanIcon);
            rescanStack.Children.Add(rescanText);
            btnRescan.Child = rescanStack;
            btnGrid.Children.Add(btnRescan);
            Grid.SetColumn(btnRescan, 2);

            stack.Children.Add(btnGrid);

            Expander exp = new Expander
            {
                Header = new TextBlock { Text = "Preview Raw Clipboard Payload", FontSize = 10.5, Foreground = _textSecondary },
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                Padding = new Thickness(6)
            };
            _rawPayloadPreview = new TextBox
            {
                Background = new SolidColorBrush(Color.FromRgb(3, 7, 18)),
                Foreground = _colorOk,
                BorderThickness = new Thickness(0),
                IsReadOnly = true,
                TextWrapping = TextWrapping.Wrap,
                FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                FontSize = 10.5,
                MaxHeight = 160,
                VerticalScrollBarVisibility = ScrollBarVisibility.Auto
            };
            exp.Content = _rawPayloadPreview;
            stack.Children.Add(exp);

            _viewResults.Children.Add(stack);
        }

        private Border CreateMatrixCard(string label, TextBlock titleBlock, TextBlock subBlock, int col, int row)
        {
            Border b = new Border
            {
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(14, 11, 14, 11),
                Margin = new Thickness(col == 0 ? 0 : 4, row == 0 ? 0 : 4, col == 0 ? 4 : 0, row == 0 ? 4 : 0)
            };

            StackPanel sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = label,
                FontSize = 9.5,
                FontWeight = FontWeights.Bold,
                Foreground = _textMuted,
                Margin = new Thickness(0, 0, 0, 3)
            });
            sp.Children.Add(titleBlock);
            sp.Children.Add(subBlock);

            b.Child = sp;
            Grid.SetColumn(b, col);
            Grid.SetRow(b, row);
            return b;
        }

        private void BuildPrivacyView()
        {
            _viewPrivacy = new Grid { Visibility = Visibility.Collapsed };
            StackPanel stack = new StackPanel();

            Border card = new Border
            {
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(16),
                Padding = new Thickness(20),
                Margin = new Thickness(0, 0, 0, 14)
            };

            StackPanel cardStack = new StackPanel();
            cardStack.Children.Add(new TextBlock
            {
                Text = "✓ Zero Data Collection Policy",
                FontSize = 13.5,
                FontWeight = FontWeights.Bold,
                Foreground = _colorOk,
                Margin = new Thickness(0, 0, 0, 6)
            });
            cardStack.Children.Add(new TextBlock
            {
                Text = "pcfix diagnostic scanner runs 100% locally on your computer using public Windows Management Instrumentation (WMI) and the Windows Event Log. No telemetry, personal files, or identifiers are transmitted to any network or cloud.",
                FontSize = 12,
                Foreground = _textSecondary,
                TextWrapping = TextWrapping.Wrap,
                LineHeight = 17
            });
            card.Child = cardStack;
            stack.Children.Add(card);

            Grid boundGrid = new Grid();
            boundGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            boundGrid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });

            Border bRead = new Border
            {
                Background = _bgCard,
                BorderBrush = new SolidColorBrush(Color.FromArgb(40, 63, 185, 80)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 4, 0)
            };
            StackPanel spRead = new StackPanel();
            spRead.Children.Add(new TextBlock { Text = "What This Tool Reads:", FontWeight = FontWeights.Bold, FontSize = 11.5, Foreground = _colorOk, Margin = new Thickness(0, 0, 0, 6) });
            spRead.Children.Add(CreateBoundItem("✓", _colorOk, "Processor model & clocks"));
            spRead.Children.Add(CreateBoundItem("✓", _colorOk, "Discrete & virtual GPUs"));
            spRead.Children.Add(CreateBoundItem("✓", _colorOk, "RAM capacity & modules"));
            spRead.Children.Add(CreateBoundItem("✓", _colorOk, "Physical disks & partitions"));
            spRead.Children.Add(CreateBoundItem("✓", _colorOk, "Disk bad blocks (Event ID 7)"));
            spRead.Children.Add(CreateBoundItem("✓", _colorOk, "Freeze reboots (Event ID 41)"));
            bRead.Child = spRead;
            boundGrid.Children.Add(bRead);
            Grid.SetColumn(bRead, 0);

            Border bNever = new Border
            {
                Background = _bgCard,
                BorderBrush = new SolidColorBrush(Color.FromArgb(40, 248, 81, 73)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(14),
                Padding = new Thickness(12),
                Margin = new Thickness(4, 0, 0, 0)
            };
            StackPanel spNever = new StackPanel();
            spNever.Children.Add(new TextBlock { Text = "What It NEVER Touches:", FontWeight = FontWeights.Bold, FontSize = 11.5, Foreground = _colorCritical, Margin = new Thickness(0, 0, 0, 6) });
            spNever.Children.Add(CreateBoundItem("✕", _colorCritical, "Zero user files or documents"));
            spNever.Children.Add(CreateBoundItem("✕", _colorCritical, "Zero browser history or cookies"));
            spNever.Children.Add(CreateBoundItem("✕", _colorCritical, "Zero passwords or tokens"));
            spNever.Children.Add(CreateBoundItem("✕", _colorCritical, "Zero webcam or keystrokes"));
            spNever.Children.Add(CreateBoundItem("✕", _colorCritical, "Zero cloud network uploads"));
            bNever.Child = spNever;
            boundGrid.Children.Add(bNever);
            Grid.SetColumn(bNever, 1);

            stack.Children.Add(boundGrid);
            _viewPrivacy.Children.Add(stack);
        }

        private UIElement CreateBoundItem(string symbol, SolidColorBrush color, string label)
        {
            StackPanel p = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 2, 0, 2) };
            p.Children.Add(new TextBlock { Text = symbol + " ", FontWeight = FontWeights.Bold, Foreground = color });
            p.Children.Add(new TextBlock { Text = label, FontSize = 10.5, Foreground = _textPrimary });
            return p;
        }

        private UIElement CreateStatusFooter()
        {
            Border f = new Border
            {
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(0, 1, 0, 0),
                Padding = new Thickness(16, 9, 16, 9)
            };

            Grid g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            TextBlock left = new TextBlock
            {
                Text = "Engine: WMI / CIM v3",
                FontSize = 10.5,
                Foreground = _textMuted,
                FontFamily = new FontFamily("Consolas, monospace")
            };
            
            StackPanel rightPanel = new StackPanel { Orientation = Orientation.Horizontal };
            TextBlock rightMem = new TextBlock
            {
                Text = "Memory: 8.4 MB   ",
                FontSize = 10.5,
                Foreground = _textSecondary
            };
            TextBlock rightSafe = new TextBlock
            {
                Text = "Offline Safe",
                FontSize = 10.5,
                Foreground = _colorOk,
                FontWeight = FontWeights.Medium
            };
            rightPanel.Children.Add(rightMem);
            rightPanel.Children.Add(rightSafe);

            g.Children.Add(left);
            Grid.SetColumn(left, 0);
            g.Children.Add(rightPanel);
            Grid.SetColumn(rightPanel, 1);

            f.Child = g;
            return f;
        }

        private void SwitchTab(bool isScan)
        {
            if (isScan)
            {
                _btnTabScanBorder.Background = _bgCard;
                _btnTabScanText.Foreground = _accent;
                _btnTabScanText.FontWeight = FontWeights.SemiBold;

                _btnTabPrivacyBorder.Background = Brushes.Transparent;
                _btnTabPrivacyText.Foreground = _textSecondary;
                _btnTabPrivacyText.FontWeight = FontWeights.Medium;

                _viewPrivacy.Visibility = Visibility.Collapsed;
                if (_viewResults.Visibility != Visibility.Visible && _viewScanning.Visibility != Visibility.Visible)
                {
                    _viewIdle.Visibility = Visibility.Visible;
                }
            }
            else
            {
                _btnTabPrivacyBorder.Background = _bgCard;
                _btnTabPrivacyText.Foreground = _accent;
                _btnTabPrivacyText.FontWeight = FontWeights.SemiBold;

                _btnTabScanBorder.Background = Brushes.Transparent;
                _btnTabScanText.Foreground = _textSecondary;
                _btnTabScanText.FontWeight = FontWeights.Medium;

                _viewIdle.Visibility = Visibility.Collapsed;
                _viewScanning.Visibility = Visibility.Collapsed;
                _viewResults.Visibility = Visibility.Collapsed;
                _viewPrivacy.Visibility = Visibility.Visible;
            }
        }

        // Scan orchestrator. UI thread only does view switching and log rendering; all WMI and
        // event-log work runs on a thread-pool thread via Task.Run. The worker reports progress
        // through ReportProgress/AppendLog (Dispatcher.BeginInvoke). A 120 s watchdog returns
        // control to the user even if a driver-level hang outlives the per-query WMI timeouts.
        private async void StartScan()
        {
            if (_isScanning) return;
            _isScanning = true;
            try
            {
                _viewIdle.Visibility = Visibility.Collapsed;
                _viewResults.Visibility = Visibility.Collapsed;
                _viewPrivacy.Visibility = Visibility.Collapsed;
                _viewScanning.Visibility = Visibility.Visible;

                _logTerminal.Text = "";
                _scanProgressBar.Value = 0;
                _scanPctText.Text = "0%";
                _scanStatusText.Text = "Starting local system scan...";
                AppendLog("INIT", "Local system scan initialized (WMI timeout 3.5 s per query)");

                Task<HardwareReport> scanTask = Task.Run(() => PerformDeepHardwareScan());
                Task finished = await Task.WhenAny(scanTask, Task.Delay(_scanWatchdog));
                if (finished != scanTask)
                {
                    AppendLog("CRIT", string.Format("Scan exceeded {0} s watchdog. A device or driver is not responding.", (int)_scanWatchdog.TotalSeconds));
                    _scanStatusText.Text = "Scan timed out. A storage device or driver may be hung.";
                    return;
                }
                if (scanTask.IsFaulted || scanTask.Result == null)
                {
                    string err = scanTask.Exception != null ? scanTask.Exception.GetBaseException().Message : "no report returned";
                    AppendLog("CRIT", "Scan failed: " + err);
                    _scanStatusText.Text = "Scan failed. See log for details.";
                    return;
                }

                HardwareReport report = scanTask.Result;
                _latestReport = report;
                ReportProgress(97, "Assembling telemetry...");

                AppendLog("OK", "CPU: " + report.Cpu);
                if (!string.IsNullOrEmpty(report.BoardProduct) && report.BoardProduct != "Unknown")
                {
                    AppendLog("OK", "Motherboard: " + report.BoardManufacturer + " " + report.BoardProduct + " (BIOS " + report.BiosVersion + ", " + report.BootMode + ")");
                }
                AppendLog("OK", "RAM: " + report.Ram);
                if (report.HasBattery)
                {
                    AppendLog("OK", "Battery: " + report.BatterySummary + " | Chassis: " + report.ChassisType);
                }

                AppendLog("OK", "GPU: " + report.Gpu);

                foreach (DiskItem d in report.Disks)
                {
                    AppendLog("DISK", string.Format("Disk {0}: {1} ({2:F0} GB) [{3}]", d.Index, d.Model, d.SizeGb, d.GetHealthBadge()));
                    if (!string.IsNullOrEmpty(d.SerialNumber))
                    {
                        AppendLog("INFO", string.Format("  Disk {0} S/N: {1} (FW: {2})", d.Index, d.SerialNumber, d.FirmwareRevision));
                    }
                }
                if (report.SplitBootDetected)
                {
                    AppendLog("INFO", "Boot configuration: " + report.SplitBootDetails);
                }

                if (report.BadBlockTotal > 0)
                {
                    AppendLog("CRIT", string.Format("CRITICAL: {0:N0} BAD BLOCK EVENTS found on {1}!", report.BadBlockTotal, report.BadBlockTargetDevice));
                    if (report.LatestRecordId > 0)
                    {
                        AppendLog("PROOF", string.Format("Live Storage Record #{0} @ {1:HH:mm:ss} -> \"{2}\"",
                            report.LatestRecordId, report.LatestRecordTime, report.SampleEventMessage));
                    }
                }
                else
                {
                    AppendLog("OK", "Event Log: 0 disk bad blocks detected (Nominal)");
                }

                if (report.WheaCount > 0)
                {
                    AppendLog("CRIT", string.Format("WHEA FAULT: {0} machine check error events detected ({1})", report.WheaCount, report.WheaSummary));
                }
                else
                {
                    AppendLog("OK", "WHEA Architecture: 0 machine check errors (Nominal)");
                }

                if (report.BugCheckCount > 0)
                {
                    AppendLog("WARN", string.Format("BugCheck BSOD: {0} ({1} recorded)", report.BugCheckSummary, report.BugCheckCount));
                }
                else
                {
                    AppendLog("OK", "BugCheck Log: 0 BSOD crashes detected (Nominal)");
                }

                if (report.DisplayTdrCount > 0)
                {
                    AppendLog("WARN", string.Format("Display TDR: {0} ({1})", report.DisplayTdrCount, report.DisplayTdrSummary));
                }

                if (report.KernelPowerEvents > 0)
                {
                    AppendLog("WARN", string.Format("Kernel-Power: {0} unexpected freeze reboots detected", report.KernelPowerEvents));
                }
                if (report.AppCrashes > 0)
                {
                    AppendLog("WARN", string.Format("Application Crashes: {0} ({1})", report.AppCrashes, report.AppCrashSummary));
                }
                if (report.SystemReliabilityScore >= 0)
                {
                    AppendLog("STAB", "Windows Reliability Index: " + report.SystemReliabilitySummary);
                }
                if (report.CpuThrottleCount > 0)
                {
                    AppendLog("WARN", string.Format("CPU Thermal/Firmware Throttling: {0} clock limit events logged!", report.CpuThrottleCount));
                }
                if (report.PnpDeviceErrors.Count > 0)
                {
                    AppendLog("WARN", string.Format("Device Manager: {0} hardware faults detected ({1})", report.PnpDeviceErrors.Count, string.Join(", ", report.PnpDeviceErrors.ToArray())));
                }
                if (report.MemDiagRan)
                {
                    if (report.MemDiagFailed) AppendLog("CRIT", "Windows Memory Diagnostic: DEFECTIVE RAM STICK DETECTED!");
                    else AppendLog("OK", "Windows Memory Diagnostic: Passed (0 memory faults)");
                }
                if (report.LowMemoryEvents > 0)
                {
                    AppendLog("WARN", string.Format("Low Virtual Memory: {0} OOM events ({1})", report.LowMemoryEvents, report.LowMemorySummary));
                }
                if (report.CmosClockDriftDetected)
                {
                    AppendLog("WARN", "Motherboard RTC Clock: Real-time clock reset logged (Dead CR2032 CMOS battery suspected)");
                }
                if (report.DeadAutoServices.Count > 0)
                {
                    AppendLog("WARN", string.Format("Dead Auto Services: {0}", string.Join(", ", report.DeadAutoServices.ToArray())));
                }
                AppendLog("INFO", string.Format("Firmware / Security: {0} | Secure Boot: {1} | C: {2} | TRIM: {3}",
                    report.TpmStatus, report.SecureBootStatus, report.BitLockerStatus, report.SsdTrimEnabled ? "Enabled" : "Disabled"));

                ReportProgress(100, "Diagnostic scan complete");
                AppendLog("DONE", "Telemetry assembled successfully");
                AppendLog("SCORE", string.Format("pcfix Score: {0}/100 ({1}) [{2}]", report.PcfixScore, report.PcfixScoreLabel, report.PcfixTier));
                if (!string.IsNullOrEmpty(report.OperationalStatusText))
                {
                    AppendLog("INFO", report.OperationalStatusText);
                }
                if (!string.IsNullOrEmpty(report.VerdictLabel))
                {
                    AppendLog(report.HasTier1HardwareFault ? "CRIT" : "INFO", report.VerdictLabel + ". " + report.VerdictAdvice);
                }
                if (report.XmpDisabledSuspected)
                {
                    AppendLog("WARN", report.XmpSummary);
                }
                await Task.Delay(350);

                PopulateResults(report);
                _viewScanning.Visibility = Visibility.Collapsed;
                _viewResults.Visibility = Visibility.Visible;
            }
            catch (Exception ex)
            {
                AppendLog("CRIT", "Unexpected scan error: " + ex.Message);
                _scanStatusText.Text = "Scan failed. See log for details.";
            }
            finally
            {
                _isScanning = false;
            }
        }

        // Thread-safe progress update. Called from the Task.Run worker; marshals to the UI thread
        // with BeginInvoke (non-blocking, so the worker never waits on the dispatcher).
        private void ReportProgress(int pct, string status)
        {
            if (Dispatcher.CheckAccess())
            {
                if (pct < 0) pct = 0;
                if (pct > 100) pct = 100;
                if (pct >= _scanProgressBar.Value) _scanProgressBar.Value = pct;
                _scanPctText.Text = string.Format("{0}%", (int)_scanProgressBar.Value);
                if (!string.IsNullOrEmpty(status)) _scanStatusText.Text = status;
            }
            else
            {
                Dispatcher.BeginInvoke(new Action(() => ReportProgress(pct, status)), DispatcherPriority.Background);
            }
        }

        private void AppendLog(string tag, string msg)
        {
            if (Dispatcher.CheckAccess())
            {
                string line = string.Format("[{0}] [{1}] {2}\r\n", DateTime.Now.ToString("HH:mm:ss.fff"), tag, msg);
                _logTerminal.AppendText(line);
                _logTerminal.ScrollToEnd();
            }
            else
            {
                Dispatcher.BeginInvoke(new Action(() => AppendLog(tag, msg)));
            }
        }

        // WMI query wrapper: applies a 3.5-second timeout via EnumerationOptions so a dying drive
        // or an unresponsive WMI provider cannot hang the scan indefinitely. Returns an empty
        // collection (never null) on timeout or failure.
        private static ManagementObjectCollection WmiGet(ManagementObjectSearcher mos)
        {
            if (mos.Options == null) mos.Options = new EnumerationOptions();
            mos.Options.Timeout = _wmiTimeout;
            mos.Options.ReturnImmediately = true;
            mos.Options.Rewindable = false;
            return mos.Get();
        }

        private static ManagementObjectCollection WmiGet(ManagementObjectSearcher mos, TimeSpan timeout)
        {
            if (mos.Options == null) mos.Options = new EnumerationOptions();
            mos.Options.Timeout = timeout;
            mos.Options.ReturnImmediately = true;
            mos.Options.Rewindable = false;
            return mos.Get();
        }

        // SMART health probe. Returns the data source actually used:
        //   "MSFT_StorageReliabilityCounter" = full counters (wear, temp, hours, read errors)
        //   "MSFT_PhysicalDisk"              = health state only (counters need Administrator)
        //   "Win32_DiskDrive"                = coarse fallback (storage namespace denied / missing)
        //   "Unavailable"                    = every probe failed
        // Never throws. Access Denied under a standard user degrades to the next tier.
        private string PopulateSmartHealth(Dictionary<int, DiskItem> diskMap)
        {
            string source = "Unavailable";
            ManagementScope storageScope = null;

            // Tier 1: MSFT_PhysicalDisk.HealthStatus (0 Healthy, 1 Warning, 2 Unhealthy, 5 Unknown)
            try
            {
                storageScope = new ManagementScope(@"root\Microsoft\Windows\Storage");
                storageScope.Options = new ConnectionOptions();
                storageScope.Options.Timeout = _wmiTimeout;
                storageScope.Connect();
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(storageScope,
                    new ObjectQuery("SELECT DeviceId, HealthStatus FROM MSFT_PhysicalDisk")))
                using (ManagementObjectCollection results = WmiGet(mos))
                {
                    foreach (ManagementObject mo in results)
                    {
                        try
                        {
                            int idx;
                            if (mo["DeviceId"] == null || !int.TryParse(mo["DeviceId"].ToString(), out idx)) continue;
                            if (!diskMap.ContainsKey(idx)) continue;
                            ushort health = mo["HealthStatus"] != null ? Convert.ToUInt16(mo["HealthStatus"]) : (ushort)5;
                            diskMap[idx].SmartHealthStatus = health == 0 ? "Healthy" : health == 1 ? "Warning" : health == 2 ? "Unhealthy" : "Unknown";
                            source = "MSFT_PhysicalDisk";
                        }
                        finally { mo.Dispose(); }
                    }
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                storageScope = null;
                AppendLog("WARN", "Storage namespace access denied, using Win32_DiskDrive fallback: " + ex.Message);
            }
            catch (ManagementException ex)
            {
                storageScope = null;
                AppendLog("WARN", string.Format("MSFT_PhysicalDisk unavailable ({0}), using Win32_DiskDrive fallback", ex.ErrorCode));
            }
            catch (Exception ex)
            {
                storageScope = null;
                AppendLog("WARN", "MSFT_PhysicalDisk query failed, using Win32_DiskDrive fallback: " + ex.Message);
            }

            // Tier 2: MSFT_StorageReliabilityCounter via association. Requires Administrator; standard
            // users get Access Denied here even when Tier 1 succeeded. Associator query keyed by
            // MSFT_PhysicalDisk ObjectId so DeviceId maps reliably to the Win32_DiskDrive index.
            if (storageScope != null)
            {
                try
                {
                    using (ManagementObjectSearcher pdSearch = new ManagementObjectSearcher(storageScope,
                        new ObjectQuery("SELECT * FROM MSFT_PhysicalDisk")))
                    using (ManagementObjectCollection disks = WmiGet(pdSearch))
                    {
                        foreach (ManagementObject pd in disks)
                        {
                            try
                            {
                                int idx;
                                if (pd["DeviceId"] == null || !int.TryParse(pd["DeviceId"].ToString(), out idx)) continue;
                                if (!diskMap.ContainsKey(idx)) continue;
                                DiskItem d = diskMap[idx];

                                using (ManagementObjectCollection counters = pd.GetRelated("MSFT_StorageReliabilityCounter"))
                                {
                                    foreach (ManagementBaseObject rc in counters)
                                    {
                                        try
                                        {
                                            if (rc["Wear"] != null) d.SmartWearPercent = Convert.ToInt32(rc["Wear"]);
                                            if (rc["Temperature"] != null)
                                            {
                                                int temp = Convert.ToInt32(rc["Temperature"]);
                                                if (temp > 0 && temp < 150) d.SmartTemperatureCelsius = temp;
                                            }
                                            if (rc["PowerOnHours"] != null) d.SmartPowerOnHours = Convert.ToInt64(rc["PowerOnHours"]);
                                            if (rc["ReadErrorsUncorrected"] != null) d.SmartReadErrorsUncorrected = Convert.ToInt64(rc["ReadErrorsUncorrected"]);
                                            source = "MSFT_StorageReliabilityCounter";
                                        }
                                        finally { rc.Dispose(); }
                                        break;
                                    }
                                }
                            }
                            finally { pd.Dispose(); }
                        }
                    }
                }
                catch (UnauthorizedAccessException)
                {
                    AppendLog("INFO", "Reliability counters need Administrator. Wear, temperature and power-on hours skipped.");
                }
                catch (ManagementException ex)
                {
                    if (ex.ErrorCode == ManagementStatus.AccessDenied)
                        AppendLog("INFO", "Reliability counters need Administrator. Wear, temperature and power-on hours skipped.");
                    else
                        AppendLog("WARN", "MSFT_StorageReliabilityCounter query failed: " + ex.ErrorCode);
                }
                catch (Exception ex)
                {
                    AppendLog("WARN", "MSFT_StorageReliabilityCounter query failed: " + ex.Message);
                }
            }

            // Tier 3: Win32_DiskDrive coarse status for any disk still Unknown. Readable by standard users.
            // Status "Pred Fail" is the SMART predictive-failure bit surfaced by the storage stack.
            bool anyUnknown = false;
            foreach (DiskItem d in diskMap.Values)
            {
                if (d.SmartHealthStatus == "Unknown") { anyUnknown = true; break; }
            }
            if (anyUnknown)
            {
                try
                {
                    using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Index, Status FROM Win32_DiskDrive"))
                    using (ManagementObjectCollection results = WmiGet(mos))
                    {
                        foreach (ManagementObject mo in results)
                        {
                            try
                            {
                                if (mo["Index"] == null) continue;
                                int idx = Convert.ToInt32(mo["Index"]);
                                if (!diskMap.ContainsKey(idx)) continue;
                                DiskItem d = diskMap[idx];
                                if (d.SmartHealthStatus != "Unknown") continue;
                                string st = mo["Status"] != null ? mo["Status"].ToString().Trim() : "";
                                if (st.Equals("Pred Fail", StringComparison.OrdinalIgnoreCase)) d.SmartHealthStatus = "Warning";
                                else if (st.Equals("Error", StringComparison.OrdinalIgnoreCase) || st.Equals("Degraded", StringComparison.OrdinalIgnoreCase)) d.SmartHealthStatus = "Unhealthy";
                                if (source == "Unavailable") source = "Win32_DiskDrive";
                            }
                            finally { mo.Dispose(); }
                        }
                    }
                }
                catch (Exception ex)
                {
                    AppendLog("WARN", "Win32_DiskDrive status fallback failed: " + ex.Message);
                }
            }

            // Tier 4: Direct Win32 IOCTL SMART (SMART_RCV_DRIVE_DATA) for drives whose wear/temp/hours
            // are still unknown. Fills the N/A gap on budget SATA SSDs. Read-only; safe when denied.
            bool anyCounterMissing = false;
            foreach (DiskItem d in diskMap.Values)
            {
                if (!d.SmartWearPercent.HasValue || !d.SmartTemperatureCelsius.HasValue || !d.SmartPowerOnHours.HasValue)
                {
                    anyCounterMissing = true;
                    break;
                }
            }
            if (anyCounterMissing)
            {
                foreach (DiskItem d in diskMap.Values)
                {
                    try
                    {
                        SataSmartIoctlReader.SmartData sd = SataSmartIoctlReader.ReadPhysicalDrive(d.Index);
                        if (sd == null) continue;

                        if (!d.SmartWearPercent.HasValue && sd.HasWear) d.SmartWearPercent = sd.WearPercent;
                        if (!d.SmartTemperatureCelsius.HasValue && sd.HasTemp) d.SmartTemperatureCelsius = sd.TemperatureCelsius;
                        if (!d.SmartPowerOnHours.HasValue && sd.HasHours) d.SmartPowerOnHours = sd.PowerOnHours;
                        if (!d.SmartReadErrorsUncorrected.HasValue && sd.HasUncorrectable) d.SmartReadErrorsUncorrected = sd.UncorrectableErrors;

                        if (sd.HasReallocated && sd.ReallocatedSectors > 0)
                        {
                            d.SmartReadErrorsUncorrected = d.SmartReadErrorsUncorrected ?? 0;
                            if (d.SmartHealthStatus == "Healthy" || d.SmartHealthStatus == "Unknown")
                            {
                                d.SmartHealthStatus = "Warning";
                            }
                            AppendLog("WARN", string.Format("Disk {0} SMART: {1} reallocated sectors (media wear)", d.Index, sd.ReallocatedSectors));
                        }
                        if ((sd.HasWear || sd.HasTemp || sd.HasHours) && source != "MSFT_StorageReliabilityCounter")
                        {
                            source = "ATA SMART (IOCTL)";
                        }
                    }
                    catch (Exception ex)
                    {
                        AppendLog("INFO", string.Format("Disk {0} IOCTL SMART unavailable: {1}", d.Index, ex.Message));
                    }
                }
            }

            foreach (DiskItem d in diskMap.Values)
            {
                if (d.SmartHealthStatus == "Unhealthy" || (d.SmartReadErrorsUncorrected ?? 0) > 0)
                {
                    AppendLog("CRIT", string.Format("Disk {0} SMART = {1} ({2} uncorrected read errors)",
                        d.Index, d.SmartHealthStatus, d.SmartReadErrorsUncorrected ?? 0));
                }
                else if (d.SmartHealthStatus == "Warning")
                {
                    AppendLog("WARN", string.Format("Disk {0} SMART = Warning (predictive failure)", d.Index));
                }
                if (d.SmartWearPercent.HasValue && d.SmartWearPercent.Value >= 90)
                {
                    AppendLog("WARN", string.Format("Disk {0} wear at {1}% of rated endurance", d.Index, d.SmartWearPercent.Value));
                }
            }
            return source;
        }

        private HardwareReport PerformDeepHardwareScan()
        {
            HardwareReport rep = new HardwareReport();
            rep.Timestamp = DateTime.Now;

            ReportProgress(5, "Scanning Win32_Processor & virtualization...");
            // 1. CPU (Win32_Processor: name, socket, cores, threads, base/max clocks; multi-socket aware)
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
                    "SELECT Name, SocketDesignation, NumberOfCores, NumberOfLogicalProcessors, CurrentClockSpeed, MaxClockSpeed FROM Win32_Processor"))
                using (ManagementObjectCollection results = WmiGet(mos))
                {
                    int socketCount = 0;
                    int totalCores = 0;
                    int totalThreads = 0;
                    string name = "Generic CPU";
                    double baseGhz = 0;
                    double maxGhz = 0;

                    foreach (ManagementObject mo in results)
                    {
                        try
                        {
                            socketCount++;
                            int c = 0;
                            int t = 0;
                            if (mo["NumberOfCores"] != null) int.TryParse(mo["NumberOfCores"].ToString(), out c);
                            if (mo["NumberOfLogicalProcessors"] != null) int.TryParse(mo["NumberOfLogicalProcessors"].ToString(), out t);
                            totalCores += c;
                            totalThreads += t;

                            if (socketCount > 1) continue;

                            if (mo["Name"] != null) name = mo["Name"].ToString().Trim();
                            if (mo["SocketDesignation"] != null) rep.CpuSocket = mo["SocketDesignation"].ToString().Trim();
                            if (mo["CurrentClockSpeed"] != null) baseGhz = Convert.ToDouble(mo["CurrentClockSpeed"]) / 1000.0;
                            if (mo["MaxClockSpeed"] != null) maxGhz = Convert.ToDouble(mo["MaxClockSpeed"]) / 1000.0;
                        }
                        finally { mo.Dispose(); }
                    }

                    if (socketCount > 0)
                    {
                        if (baseGhz == 0) baseGhz = maxGhz;
                        if (maxGhz == 0) maxGhz = baseGhz;
                        rep.CpuCoreCount = totalCores;
                        rep.CpuThreadCount = totalThreads;

                        string cleanName = Regex.Replace(name, @"\((R|TM)\)", "", RegexOptions.IgnoreCase).Trim();
                        cleanName = Regex.Replace(cleanName, @"\s+", " ");
                        if (socketCount > 1) cleanName = string.Format("{0}x {1}", socketCount, cleanName);
                        rep.CpuName = cleanName;

                        string socketStr = !string.IsNullOrEmpty(rep.CpuSocket) ? " | " + rep.CpuSocket : "";
                        if (Math.Abs(baseGhz - maxGhz) > 0.05 && baseGhz > 0 && maxGhz > 0)
                        {
                            rep.CpuDetail = string.Format("{0} Cores / {1} Threads | {2:F2} GHz Base / {3:F2} GHz Max{4}", totalCores, totalThreads, baseGhz, maxGhz, socketStr);
                        }
                        else
                        {
                            rep.CpuDetail = string.Format("{0} Cores / {1} Threads | {2:F2} GHz{3}", totalCores, totalThreads, maxGhz, socketStr);
                        }
                        rep.Cpu = string.Format("{0} ({1}C/{2}T @ {3:F2} GHz{4})", cleanName, totalCores, totalThreads, maxGhz,
                            !string.IsNullOrEmpty(rep.CpuSocket) ? ", " + rep.CpuSocket : "");
                    }
                }
            }
            catch (Exception ex)
            {
                rep.CpuName = "x64 Processor";
                rep.CpuDetail = "Clock info unavailable";
                rep.Cpu = "x64 Processor (" + ex.Message + ")";
            }

            // 1a. Virtualization (Win32_ComputerSystem.HypervisorPresent; Win8+ property)
            // True when Hyper-V, VBS/HVCI, WSL2 or a guest VM hypervisor is active. Event 37 throttling
            // and clock readings are less reliable under a hypervisor, so this is surfaced as context.
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT HypervisorPresent FROM Win32_ComputerSystem"))
                using (ManagementObjectCollection results = WmiGet(mos))
                {
                    foreach (ManagementObject mo in results)
                    {
                        try
                        {
                            if (mo["HypervisorPresent"] != null) rep.HypervisorPresent = Convert.ToBoolean(mo["HypervisorPresent"]);
                        }
                        finally { mo.Dispose(); }
                        break;
                    }
                }
            }
            catch (ManagementException)
            {
                // Pre-Win8 WMI schema lacks HypervisorPresent; leave false.
            }
            catch { }

            ReportProgress(10, "Reading motherboard & firmware...");
            // 1b. Motherboard & Firmware (Win32_BaseBoard, Win32_BIOS, UEFI detection)
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Manufacturer, Product FROM Win32_BaseBoard"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        if (mo["Manufacturer"] != null) rep.BoardManufacturer = mo["Manufacturer"].ToString().Trim();
                        if (mo["Product"] != null) rep.BoardProduct = mo["Product"].ToString().Trim();
                        break;
                    }
                }
                if (string.IsNullOrEmpty(rep.BoardProduct) || rep.BoardProduct.IndexOf("Base Board", StringComparison.OrdinalIgnoreCase) >= 0 || rep.BoardProduct.IndexOf("Product Name", StringComparison.OrdinalIgnoreCase) >= 0 || rep.BoardProduct.IndexOf("Default", StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    using (ManagementObjectSearcher mosCs = new ManagementObjectSearcher("SELECT Manufacturer, Model FROM Win32_ComputerSystem"))
                    {
                        foreach (ManagementObject mo in WmiGet(mosCs))
                        {
                            string csMan = mo["Manufacturer"] != null ? mo["Manufacturer"].ToString().Trim() : "";
                            string csMod = mo["Model"] != null ? mo["Model"].ToString().Trim() : "";
                            if (!string.IsNullOrEmpty(csMod) && csMod.IndexOf("Product Name", StringComparison.OrdinalIgnoreCase) < 0)
                            {
                                if (!string.IsNullOrEmpty(csMan) && (string.IsNullOrEmpty(rep.BoardManufacturer) || rep.BoardManufacturer.IndexOf("Manufacturer", StringComparison.OrdinalIgnoreCase) >= 0))
                                {
                                    rep.BoardManufacturer = csMan;
                                }
                                rep.BoardProduct = csMod;
                            }
                            break;
                        }
                    }
                }
            }
            catch { }
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT SMBIOSBIOSVersion, ReleaseDate FROM Win32_BIOS"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        if (mo["SMBIOSBIOSVersion"] != null)
                        {
                            object v = mo["SMBIOSBIOSVersion"];
                            if (v is string[]) rep.BiosVersion = string.Join(", ", (string[])v);
                            else rep.BiosVersion = v.ToString().Trim();
                        }
                        else if (mo["BIOSVersion"] != null)
                        {
                            object v = mo["BIOSVersion"];
                            if (v is string[]) rep.BiosVersion = string.Join(", ", (string[])v);
                            else rep.BiosVersion = v.ToString().Trim();
                        }
                        if (mo["ReleaseDate"] != null)
                        {
                            try { rep.BiosDate = ManagementDateTimeConverter.ToDateTime(mo["ReleaseDate"].ToString()).ToString("yyyy-MM-dd"); } catch { }
                        }
                        break;
                    }
                }
            }
            catch { }
            try
            {
                // UEFI vs Legacy: check Win32_ComputerSystem BootupState or SecureBoot via registry-like WMI
                // Use Win32_ComputerSystem for BootupState and check firmware type via Win32_BIOS BIOSCharacteristics
                // Most reliable pure WMI: query Win32_Firmware? fallback to checking SystemDrive EFI partition existence
                // Here: detect via Win32_ComputerSystem + Win32_DiskPartition Type containing EFI
                bool isUefi = false;
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Caption FROM Win32_DiskPartition WHERE Type LIKE '%EFI%' OR Type LIKE '%GPT%'"))
                {
                    foreach (ManagementObject mo in WmiGet(mos)) { isUefi = true; break; }
                }
                if (!isUefi)
                {
                    try
                    {
                        string sysDrive = Environment.GetEnvironmentVariable("SystemDrive");
                        if (!string.IsNullOrEmpty(sysDrive))
                        {
                            string efiTest = System.IO.Path.Combine(sysDrive, "EFI");
                            // Check via bcdedit-free method: if SystemPartition exists on GPT, assume UEFI
                            isUefi = Directory.Exists(@"C:\Windows\Boot\EFI") || Directory.Exists(@"C:\EFI");
                        }
                    }
                    catch { }
                }
                rep.BootMode = isUefi ? "UEFI" : "Legacy / UEFI-CSM";
            }
            catch { rep.BootMode = "Unknown"; }

            ReportProgress(15, "Querying Win32_PhysicalMemory & XMP state...");
            // 2. RAM (Win32_PhysicalMemory: per-slot inventory, DDR gen, channel, XMP/EXPO lock)
            // Speed = module rated max (SPD / XMP profile ceiling reported by SMBIOS Type 17).
            // ConfiguredClockSpeed = speed the memory controller actually trained to at boot.
            // When Configured sits at a JEDEC base (2133/2400/2666/3200 DDR4, 4800/5600 DDR5)
            // while Speed is clearly higher, the XMP/EXPO profile is not enabled in BIOS.
            try
            {
                ulong totalBytes = 0;
                uint ratedMax = 0;
                uint configuredMin = 0;
                int moduleCount = 0;
                int ddrType = 0;
                int totalSlots = 0;
                try
                {
                    using (ManagementObjectSearcher mosArr = new ManagementObjectSearcher("SELECT MemoryDevices FROM Win32_PhysicalMemoryArray"))
                    using (ManagementObjectCollection arrResults = WmiGet(mosArr))
                    {
                        foreach (ManagementObject mo in arrResults)
                        {
                            try
                            {
                                if (mo["MemoryDevices"] != null) totalSlots += Convert.ToInt32(mo["MemoryDevices"]);
                            }
                            finally { mo.Dispose(); }
                        }
                    }
                }
                catch { }

                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
                    "SELECT BankLabel, DeviceLocator, Capacity, Speed, ConfiguredClockSpeed, SMBIOSMemoryType, Manufacturer, PartNumber FROM Win32_PhysicalMemory"))
                using (ManagementObjectCollection results = WmiGet(mos))
                {
                    foreach (ManagementObject mo in results)
                    {
                        try
                        {
                            ulong cap = 0;
                            if (mo["Capacity"] != null) try { cap = Convert.ToUInt64(mo["Capacity"]); } catch { }
                            totalBytes += cap;

                            uint rated = 0;
                            uint configured = 0;
                            if (mo["Speed"] != null) try { rated = Convert.ToUInt32(mo["Speed"]); } catch { }
                            if (mo["ConfiguredClockSpeed"] != null) try { configured = Convert.ToUInt32(mo["ConfiguredClockSpeed"]); } catch { }
                            uint partRated = ParseRatedSpeedFromPartNumber(mo["PartNumber"] != null ? mo["PartNumber"].ToString() : "");
                            if (partRated > rated) rated = partRated;
                            if (rated > ratedMax) ratedMax = rated;
                            if (configured > 0 && (configuredMin == 0 || configured < configuredMin)) configuredMin = configured;

                            if (ddrType == 0 && mo["SMBIOSMemoryType"] != null) try { ddrType = Convert.ToInt32(mo["SMBIOSMemoryType"]); } catch { }

                            string slot = mo["DeviceLocator"] != null ? mo["DeviceLocator"].ToString().Trim() : "";
                            if (string.IsNullOrEmpty(slot) && mo["BankLabel"] != null) slot = mo["BankLabel"].ToString().Trim();
                            if (string.IsNullOrEmpty(slot)) slot = string.Format("Slot {0}", moduleCount);
                            string vendor = mo["Manufacturer"] != null ? mo["Manufacturer"].ToString().Trim() : "";
                            string part = mo["PartNumber"] != null ? mo["PartNumber"].ToString().Trim() : "";
                            if (vendor.Length == 0 || vendor.Equals("Unknown", StringComparison.OrdinalIgnoreCase) || Regex.IsMatch(vendor, @"^0+$")) vendor = "Unknown vendor";
                            if (part.Length == 0) part = "No part number";

                            rep.RamModules.Add(string.Format("{0}: {1:F0} GB {2} {3} ({4}/{5} MT/s)",
                                slot, cap / (1024.0 * 1024.0 * 1024.0), vendor, part,
                                configured > 0 ? configured.ToString() : "?",
                                rated > 0 ? rated.ToString() : "?"));
                            moduleCount++;
                        }
                        finally { mo.Dispose(); }
                    }
                }

                rep.RamRatedSpeed = ratedMax;
                rep.RamConfiguredSpeed = configuredMin;

                // XMP/EXPO lock heuristic. Require a 10%+ gap so normal SPD rounding (3200 vs 3192)
                // and JEDEC-only kits (rated == configured) never trigger a false warning.
                if (ratedMax > 0 && configuredMin > 0 && ratedMax > configuredMin && (ratedMax - configuredMin) * 10 >= ratedMax)
                {
                    rep.XmpDisabledSuspected = true;
                    rep.XmpSummary = string.Format("Running {0} MT/s, modules rated {1} MT/s. XMP/EXPO profile likely disabled in BIOS.", configuredMin, ratedMax);
                }
                else if (ratedMax > 0 && configuredMin > 0)
                {
                    rep.XmpSummary = string.Format("Running {0} MT/s (rated {1} MT/s)", configuredMin, ratedMax);
                }

                if (totalBytes == 0)
                {
                    rep.RamName = "Not detected";
                    rep.RamDetail = "No DIMM data returned";
                    rep.Ram = "System Memory: Not detected";
                }
                else
                {
                    double totalGb = Math.Round((double)totalBytes / (1024.0 * 1024.0 * 1024.0), 1);
                    string channelStr = "Single-Channel";
                    if (moduleCount == 4) channelStr = "Quad-Channel";
                    else if (moduleCount >= 2 && moduleCount % 2 == 0) channelStr = "Dual-Channel";
                    else if (moduleCount > 1) channelStr = string.Format("{0} modules", moduleCount);
                    string ddrStr = "DDR";
                    if (ddrType == 21) ddrStr = "DDR2";
                    else if (ddrType == 24) ddrStr = "DDR3";
                    else if (ddrType == 26) ddrStr = "DDR4";
                    else if (ddrType == 34) ddrStr = "DDR5";
                    uint shownSpeed = configuredMin > 0 ? configuredMin : ratedMax;
                    string speedStr = shownSpeed > 0 ? shownSpeed.ToString() : "Auto";
                    string slotInfo = totalSlots > 0 ? string.Format("{0}/{1} slots", moduleCount, totalSlots) : string.Format("{0} modules", moduleCount);
                    rep.RamName = string.Format("{0:F1} GB {1}", totalGb, ddrStr);
                    rep.RamDetail = string.Format("{0} | {1} | {2} MT/s{3}", channelStr, slotInfo, speedStr, rep.XmpDisabledSuspected ? " | XMP OFF" : "");
                    rep.Ram = string.Format("{0:F1} GB {1} ({2}, {3} @ {4} MT/s)", totalGb, ddrStr, slotInfo, channelStr, speedStr);
                }
            }
            catch (Exception ex)
            {
                rep.RamName = "Not detected";
                rep.RamDetail = ex.Message;
                rep.Ram = "System Memory: query failed (" + ex.Message + ")";
            }

            ReportProgress(22, "Inspecting Win32_VideoController & display drivers...");
            // 3. Multi-GPU Enumeration (Win32_VideoController: discrete + integrated, driver, resolution, status)
            try
            {
                List<string> gpus = new List<string>();
                string firstGpuName = "";
                string firstGpuDriver = "";
                string firstGpuRes = "";
                string firstGpuStatus = "";
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Name, DriverVersion, VideoProcessor, CurrentHorizontalResolution, CurrentVerticalResolution, CurrentRefreshRate, Status FROM Win32_VideoController"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        string name = mo["Name"] != null ? mo["Name"].ToString().Trim() : "Display Adapter";
                        string driver = mo["DriverVersion"] != null ? mo["DriverVersion"].ToString().Trim() : "";
                        string status = mo["Status"] != null ? mo["Status"].ToString().Trim() : "OK";
                        string res = "";
                        if (mo["CurrentHorizontalResolution"] != null && mo["CurrentVerticalResolution"] != null)
                        {
                            try
                            {
                                int w = Convert.ToInt32(mo["CurrentHorizontalResolution"]);
                                int h = Convert.ToInt32(mo["CurrentVerticalResolution"]);
                                if (w > 0 && h > 0)
                                {
                                    if (mo["CurrentRefreshRate"] != null)
                                    {
                                        int rr = Convert.ToInt32(mo["CurrentRefreshRate"]);
                                        if (rr > 0) res = string.Format("{0}x{1} @ {2}Hz", w, h, rr);
                                        else res = string.Format("{0}x{1}", w, h);
                                    }
                                    else
                                    {
                                        res = string.Format("{0}x{1}", w, h);
                                    }
                                }
                            }
                            catch { }
                        }

                        bool isDiscrete = name.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                          name.IndexOf("GeForce", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                          name.IndexOf("Radeon", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                          name.IndexOf("AMD", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                          name.IndexOf("Arc", StringComparison.OrdinalIgnoreCase) >= 0;
                        bool isVirtual = name.IndexOf("Virtual", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         name.IndexOf("Basic Display", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                         name.IndexOf("Remote", StringComparison.OrdinalIgnoreCase) >= 0;
                        bool hasRes = !string.IsNullOrEmpty(res);

                        if (string.IsNullOrEmpty(firstGpuName) || 
                            (firstGpuName.IndexOf("Virtual", StringComparison.OrdinalIgnoreCase) >= 0 && !isVirtual) ||
                            (!string.IsNullOrEmpty(firstGpuName) && string.IsNullOrEmpty(firstGpuRes) && hasRes) ||
                            (!string.IsNullOrEmpty(firstGpuName) && isDiscrete && firstGpuName.IndexOf("NVIDIA", StringComparison.OrdinalIgnoreCase) < 0 && firstGpuName.IndexOf("Radeon", StringComparison.OrdinalIgnoreCase) < 0))
                        {
                            firstGpuName = name;
                            firstGpuDriver = driver;
                            firstGpuRes = res;
                            firstGpuStatus = status;
                        }

                        string desc = name;
                        if (!string.IsNullOrEmpty(driver)) desc = string.Format("{0} (Driver v{1})", name, driver);
                        if (!string.IsNullOrEmpty(res)) desc += " [" + res + "]";

                        if (!gpus.Contains(desc))
                        {
                            gpus.Add(desc);
                        }
                    }
                }
                rep.GpuName = !string.IsNullOrEmpty(firstGpuName) ? firstGpuName : "Display Adapter";
                if (!string.IsNullOrEmpty(firstGpuRes) && !string.IsNullOrEmpty(firstGpuDriver))
                {
                    rep.GpuDetail = string.Format("Driver v{0} | {1} | {2}", firstGpuDriver, firstGpuRes, firstGpuStatus);
                }
                else if (!string.IsNullOrEmpty(firstGpuDriver))
                {
                    rep.GpuDetail = string.Format("Driver v{0} | {1}", firstGpuDriver, firstGpuStatus);
                }
                else if (!string.IsNullOrEmpty(firstGpuRes))
                {
                    rep.GpuDetail = string.Format("{0} | {1}", firstGpuRes, firstGpuStatus);
                }
                else
                {
                    rep.GpuDetail = string.IsNullOrEmpty(firstGpuStatus) ? "Active Display Driver" : firstGpuStatus;
                }
                rep.Gpu = gpus.Count > 0 ? string.Join(" + ", gpus.ToArray()) : "Standard Display Adapter";

                // Upgrade 2: PCIe link validation for the discrete GPU (sag / dirty-slot detection).
                try
                {
                    PcieLinkSpeedDetector.GpuLinkState ls = PcieLinkSpeedDetector.DetectDiscreteGpu();
                    if (ls != null)
                    {
                        string cur = PcieLinkSpeedDetector.DescribeLink(ls.CurrentWidth, ls.CurrentSpeed);
                        string max = PcieLinkSpeedDetector.DescribeLink(ls.MaxWidth, ls.MaxSpeed);
                        rep.GpuPcieLink = cur;
                        rep.GpuPcieDetail = string.Format("{0} ({1}) negotiated, max {2} ({3})",
                            cur, PcieLinkSpeedDetector.DescribeSpeed(ls.CurrentSpeed),
                            max, PcieLinkSpeedDetector.DescribeSpeed(ls.MaxSpeed));
                        // Flag when a discrete GPU negotiated fewer than x8 lanes (card sag or bad slot pins).
                        if (ls.CurrentWidth > 0 && ls.CurrentWidth < 8)
                        {
                            rep.GpuPcieCrippled = true;
                            AppendLog("CRIT", string.Format("GPU PCIe Link Crippled: {0} detected (max {1}). Re-seat the card or check slot pins.", cur, max));
                        }
                        else
                        {
                            AppendLog("OK", string.Format("GPU PCIe Link: {0} (max {1})", cur, max));
                        }
                    }
                }
                catch (Exception ex)
                {
                    AppendLog("INFO", "GPU PCIe link query unavailable: " + ex.Message);
                }
            }
            catch
            {
                rep.GpuName = "Graphics Adapter";
                rep.GpuDetail = "Standard Driver";
                rep.Gpu = "Graphics Device (Standard Driver)";
            }

            ReportProgress(30, "Mapping disks, partitions & SMART health...");
            // 4. Multi-Disk Enumeration & Topology Mapping (Win32_DiskDrive baseline; always available to standard users)
            Dictionary<int, DiskItem> diskMap = new Dictionary<int, DiskItem>();
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
                    "SELECT Index, Model, Size, Status, InterfaceType, SerialNumber, FirmwareRevision FROM Win32_DiskDrive"))
                using (ManagementObjectCollection results = WmiGet(mos))
                {
                    foreach (ManagementObject mo in results)
                    {
                        try
                        {
                            if (mo["Index"] == null) continue;
                            int idx = Convert.ToInt32(mo["Index"]);
                            DiskItem d = new DiskItem();
                            d.Index = idx;
                            d.Model = mo["Model"] != null ? mo["Model"].ToString().Trim() : "Disk " + idx;
                            d.Status = mo["Status"] != null ? mo["Status"].ToString().Trim() : "OK";
                            d.SerialNumber = mo["SerialNumber"] != null ? mo["SerialNumber"].ToString().Trim() : "";
                            d.FirmwareRevision = mo["FirmwareRevision"] != null ? mo["FirmwareRevision"].ToString().Trim() : "";
                            if (mo["InterfaceType"] != null && mo["InterfaceType"].ToString().Trim().Equals("USB", StringComparison.OrdinalIgnoreCase)) d.InterfaceType = "USB";
                            if (mo["Size"] != null) d.SizeGb = Math.Round(Convert.ToDouble(mo["Size"]) / (1024.0 * 1024.0 * 1024.0), 0);
                            diskMap[idx] = d;
                        }
                        finally { mo.Dispose(); }
                    }
                }

                // 4a. Split-Boot Shield: locate the Windows volume (C:) disk and the ACTIVE EFI System Partition disk.
                int osDiskIndex = -1;
                int activeEspDiskIndex = -1;
                List<int> espDiskIndexes = new List<int>();

                // Windows volume disk: Win32_LogicalDiskToPartition association (standard user OK).
                string sysDrive = Environment.GetEnvironmentVariable("SystemDrive");
                if (string.IsNullOrEmpty(sysDrive)) sysDrive = "C:";
                try
                {
                    using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Antecedent, Dependent FROM Win32_LogicalDiskToPartition"))
                    using (ManagementObjectCollection results = WmiGet(mos))
                    {
                        foreach (ManagementObject mo in results)
                        {
                            try
                            {
                                string ante = mo["Antecedent"] != null ? mo["Antecedent"].ToString() : "";
                                string dep = mo["Dependent"] != null ? mo["Dependent"].ToString() : "";
                                Match mDisk = Regex.Match(ante, @"Disk #(\d+)");
                                Match mLetter = Regex.Match(dep, @"DeviceID=""([A-Za-z]:)""");
                                if (!mDisk.Success || !mLetter.Success) continue;

                                int dIdx;
                                if (!int.TryParse(mDisk.Groups[1].Value, out dIdx)) continue;
                                string letter = mLetter.Groups[1].Value.ToUpperInvariant();
                                if (!diskMap.ContainsKey(dIdx)) continue;
                                if (!diskMap[dIdx].Volumes.Contains(letter)) diskMap[dIdx].Volumes.Add(letter);
                                if (letter.Equals(sysDrive, StringComparison.OrdinalIgnoreCase))
                                {
                                    diskMap[dIdx].IsWindowsOs = true;
                                    osDiskIndex = dIdx;
                                }
                            }
                            finally { mo.Dispose(); }
                        }
                    }
                }
                catch { }

                // Active ESP, primary source: MSFT_Partition.IsSystem. Windows sets IsSystem only on the
                // partition the firmware actually booted from, so a stale ESP on a second disk does not count.
                bool storageNamespaceOk = false;
                try
                {
                    ManagementScope storageScope = new ManagementScope(@"root\Microsoft\Windows\Storage");
                    storageScope.Options = new ConnectionOptions();
                    storageScope.Options.Timeout = _wmiTimeout;
                    storageScope.Connect();
                    using (ManagementObjectSearcher mos = new ManagementObjectSearcher(storageScope,
                        new ObjectQuery("SELECT DiskNumber, IsSystem, GptType FROM MSFT_Partition")))
                    using (ManagementObjectCollection results = WmiGet(mos))
                    {
                        foreach (ManagementObject mo in results)
                        {
                            try
                            {
                                storageNamespaceOk = true;
                                if (mo["DiskNumber"] == null) continue;
                                int dIdx = Convert.ToInt32(mo["DiskNumber"]);
                                string gpt = mo["GptType"] != null ? mo["GptType"].ToString() : "";
                                bool isEsp = gpt.IndexOf("c12a7328-f81f-11d2-ba4b-00a0c93ec93b", StringComparison.OrdinalIgnoreCase) >= 0;
                                bool isSystem = mo["IsSystem"] != null && Convert.ToBoolean(mo["IsSystem"]);
                                if (isEsp && !espDiskIndexes.Contains(dIdx)) espDiskIndexes.Add(dIdx);
                                if (isSystem)
                                {
                                    activeEspDiskIndex = dIdx;
                                    if (diskMap.ContainsKey(dIdx)) diskMap[dIdx].IsBootloader = true;
                                }
                            }
                            finally { mo.Dispose(); }
                        }
                    }
                }
                catch (UnauthorizedAccessException) { storageNamespaceOk = false; }
                catch (ManagementException) { storageNamespaceOk = false; }
                catch { storageNamespaceOk = false; }

                // Active ESP, fallback: Win32_DiskPartition (no IsSystem; "GPT: System" type or MBR active flag).
                if (activeEspDiskIndex < 0)
                {
                    try
                    {
                        using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT DiskIndex, BootPartition, Type FROM Win32_DiskPartition"))
                        using (ManagementObjectCollection results = WmiGet(mos))
                        {
                            foreach (ManagementObject mo in results)
                            {
                                try
                                {
                                    if (mo["DiskIndex"] == null) continue;
                                    int dIdx = Convert.ToInt32(mo["DiskIndex"]);
                                    string type = mo["Type"] != null ? mo["Type"].ToString() : "";
                                    bool isActive = mo["BootPartition"] != null && Convert.ToBoolean(mo["BootPartition"]);
                                    bool isEsp = type.IndexOf("GPT: System", StringComparison.OrdinalIgnoreCase) >= 0;
                                    if ((isEsp || isActive) && !espDiskIndexes.Contains(dIdx)) espDiskIndexes.Add(dIdx);
                                }
                                finally { mo.Dispose(); }
                            }
                        }
                    }
                    catch { }

                    // Without IsSystem we cannot know which ESP firmware used. If the OS disk has its own ESP,
                    // assume self-contained boot (conservative: avoids false split-boot alarms on multi-ESP rigs).
                    if (osDiskIndex >= 0 && espDiskIndexes.Contains(osDiskIndex)) activeEspDiskIndex = osDiskIndex;
                    else if (espDiskIndexes.Count == 1) activeEspDiskIndex = espDiskIndexes[0];

                    if (activeEspDiskIndex >= 0 && diskMap.ContainsKey(activeEspDiskIndex)) diskMap[activeEspDiskIndex].IsBootloader = true;
                }

                if (activeEspDiskIndex >= 0 && osDiskIndex >= 0 && activeEspDiskIndex != osDiskIndex)
                {
                    rep.SplitBootDetected = true;
                    string efiModel = diskMap.ContainsKey(activeEspDiskIndex) ? diskMap[activeEspDiskIndex].Model : "Disk " + activeEspDiskIndex;
                    string osModel = diskMap.ContainsKey(osDiskIndex) ? diskMap[osDiskIndex].Model : "Disk " + osDiskIndex;
                    rep.SplitBootDetails = string.Format(
                        "Boot Configuration Note: the active bootloader (EFI System Partition) is on Disk {0} ({1}), while Windows {2} is on Disk {3} ({4}). System boots normally; keep both drives connected.{5}",
                        activeEspDiskIndex, efiModel, sysDrive, osDiskIndex, osModel,
                        storageNamespaceOk ? "" : " (Detected via Win32_DiskPartition fallback.)");
                }

                // 4b. SMART / Storage Reliability (MSFT_PhysicalDisk + MSFT_StorageReliabilityCounter, Win32_DiskDrive fallback)
                AppendLog("INFO", "Querying SMART reliability counters (MSFT_StorageReliabilityCounter)...");
                rep.SmartSource = PopulateSmartHealth(diskMap);

                List<DiskItem> sortedDisks = new List<DiskItem>(diskMap.Values);
                sortedDisks.Sort((a, b) => a.Index.CompareTo(b.Index));
                rep.Disks = sortedDisks;

                List<string> diskSummaries = new List<string>();
                List<string> diskModels = new List<string>();
                foreach (DiskItem d in rep.Disks)
                {
                    diskSummaries.Add(string.Format("Disk {0}: {1} ({2:F0} GB)", d.Index, d.Model, d.SizeGb));
                    diskModels.Add(string.Format("{0} ({1:F0} GB)", d.Model, d.SizeGb));
                }
                rep.StorageSummary = string.Join(" | ", diskSummaries.ToArray());
                rep.StorageName = diskModels.Count > 0 ? string.Join(" + ", diskModels.ToArray()) : "Physical Storage";
                if (rep.Disks.Exists(d => d.SmartHealthStatus == "Unhealthy" || (d.SmartReadErrorsUncorrected ?? 0) > 0))
                {
                    rep.StorageDetail = "SMART FAILURE DETECTED | Critical";
                }
                else if (rep.Disks.Exists(d => d.SmartHealthStatus == "Warning"))
                {
                    rep.StorageDetail = string.Format("SMART Warning | {0} Disks", rep.Disks.Count);
                }
                else if (rep.Disks.Exists(d => d.SmartHealthStatus == "Healthy"))
                {
                    rep.StorageDetail = string.Format("SMART Verified Healthy | {0} Disks", rep.Disks.Count);
                }
                else
                {
                    rep.StorageDetail = string.Format("{0} Disks (SMART Unavailable)", rep.Disks.Count);
                }
            }
            catch (Exception ex)
            {
                rep.StorageName = "Physical Storage";
                rep.StorageDetail = "Storage Query Error";
                rep.StorageSummary = "Storage Disks (" + ex.Message + ")";
            }

            ReportProgress(45, "Auditing disk bad blocks (Event 7/51/153)...");
            // 5. Windows Event Log Deep Audit
            try
            {
                string queryStr = "*[System[Provider[@Name='disk'] and (EventID=7 or EventID=51 or EventID=153)]]";
                EventLogQuery query = new EventLogQuery("System", PathType.LogName, queryStr);
                query.ReverseDirection = true;

                int badBlockCount = 0;
                Dictionary<int, int> diskBadBlocks = new Dictionary<int, int>();
                string targetDev = "";

                using (EventLogReader reader = new EventLogReader(query))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            badBlockCount++;
                            string desc = "";
                            try { desc = rec.FormatDescription(); } catch { }

                            if (badBlockCount == 1)
                            {
                                try
                                {
                                    if (rec.RecordId.HasValue) rep.LatestRecordId = rec.RecordId.Value;
                                    if (rec.TimeCreated.HasValue) rep.LatestRecordTime = rec.TimeCreated.Value;
                                    rep.SampleEventMessage = desc;
                                }
                                catch { }
                            }

                            if (string.IsNullOrEmpty(targetDev) && !string.IsNullOrEmpty(desc))
                            {
                                Match mDev = Regex.Match(desc, @"\\Device\\Harddisk(\d+)", RegexOptions.IgnoreCase);
                                if (mDev.Success)
                                {
                                    targetDev = mDev.Value;
                                }
                            }

                            if (!string.IsNullOrEmpty(desc))
                            {
                                Match mNum = Regex.Match(desc, @"\\Device\\Harddisk(\d+)", RegexOptions.IgnoreCase);
                                if (mNum.Success)
                                {
                                    int dNum;
                                    if (!int.TryParse(mNum.Groups[1].Value, out dNum)) continue;
                                    if (!diskBadBlocks.ContainsKey(dNum)) diskBadBlocks[dNum] = 0;
                                    diskBadBlocks[dNum]++;
                                }
                            }

                            if (badBlockCount >= 50000) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }

                rep.BadBlockTotal = badBlockCount;
                rep.BadBlockTargetDevice = !string.IsNullOrEmpty(targetDev) ? targetDev : (badBlockCount > 0 ? @"\Device\Harddisk1" : "None");

                foreach (KeyValuePair<int, int> kv in diskBadBlocks)
                {
                    if (diskMap.ContainsKey(kv.Key))
                    {
                        diskMap[kv.Key].BadBlockCount = kv.Value;
                    }
                }

                if (rep.BadBlockTotal > 0)
                {
                    rep.StorageDetail = string.Format("{0:N0} Read Retries | Maintenance", rep.BadBlockTotal);
                }
            }
            catch { }

            ReportProgress(52, "Decoding Kernel-Power 41 bugchecks...");
            // 6. Kernel-Power Event 41: unclean shutdowns (7 days) + BugcheckCode decode.
            // EventData "BugcheckCode" is decimal (292 = 0x124). 0 means hard power loss or a freeze
            // with no bugcheck (PSU, thermal trip, power button hold), not a BSOD.
            try
            {
                DateTime cutoff = DateTime.Now.AddDays(-7);
                string kpQuery = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Power'] and EventID=41]]";
                EventLogQuery queryKp = new EventLogQuery("System", PathType.LogName, kpQuery);
                queryKp.ReverseDirection = true;

                int kpCount = 0;
                int scanned = 0;
                uint latestBugcheck = 0;
                using (EventLogReader reader = new EventLogReader(queryKp))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            scanned++;
                            bool inWindow = !rec.TimeCreated.HasValue || rec.TimeCreated.Value >= cutoff;
                            if (inWindow) kpCount++;

                            if (latestBugcheck == 0)
                            {
                                uint code = ExtractEventDataUInt(rec, "BugcheckCode", 0);
                                if (code != 0) latestBugcheck = code;
                            }

                            if (!inWindow && latestBugcheck != 0) break;
                            if (scanned >= 200) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }
                rep.KernelPowerEvents = kpCount;
                if (latestBugcheck != 0)
                {
                    rep.KernelPowerStopCode = DecodeStopCode(latestBugcheck);
                    if (string.IsNullOrEmpty(rep.BugCheckStopCode)) rep.BugCheckStopCode = rep.KernelPowerStopCode;
                }

                // Upgrade 4: discriminate the cause of the most recent Event 41 (if any).
                if (kpCount > 0)
                {
                    try
                    {
                        using (EventLogReader vr = new EventLogReader(queryKp))
                        {
                            EventRecord rec = vr.ReadEvent();
                            if (rec != null)
                            {
                                try
                                {
                                    KernelPowerEventDecoder.Event41 e = KernelPowerEventDecoder.Parse(rec);
                                    if (e != null)
                                    {
                                        rep.KernelPowerVerdict = KernelPowerEventDecoder.Verdict(e);
                                        if (rec.TimeCreated.HasValue) rep.KernelPowerLatestTime = rec.TimeCreated.Value;
                                        AppendLog("INFO", "Event 41 cause: " + rep.KernelPowerVerdict);
                                    }
                                }
                                finally { rec.Dispose(); }
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        AppendLog("INFO", "Event 41 discriminator failed: " + ex.Message);
                    }
                }
            }
            catch (EventLogNotFoundException) { }
            catch (UnauthorizedAccessException) { }
            catch { }

            // 7. Application Error (Event 1000)
            try
            {
                string appQuery = "*[System[Provider[@Name='Application Error'] and EventID=1000]]";
                EventLogQuery queryApp = new EventLogQuery("Application", PathType.LogName, appQuery);
                queryApp.ReverseDirection = true;

                int appErrCount = 0;
                List<string> faultApps = new List<string>();

                using (EventLogReader reader = new EventLogReader(queryApp))
                {
                    int scannedCount = 0;
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            scannedCount++;
                            string desc = "";
                            try { desc = rec.FormatDescription(); } catch { }

                            if (!string.IsNullOrEmpty(desc))
                            {
                                if (desc.Contains("0xc0000374") || desc.Contains("0xc0000005"))
                                {
                                    appErrCount++;
                                    Match mApp = Regex.Match(desc, @"Faulting application name:\s*([^\r\n,]+)", RegexOptions.IgnoreCase);
                                    if (mApp.Success)
                                    {
                                        string appName = mApp.Groups[1].Value.Trim();
                                        if (!faultApps.Contains(appName))
                                        {
                                            faultApps.Add(appName);
                                        }
                                    }
                                }
                            }
                            if (appErrCount >= 20) break;
                            // Not every Application-Error 1000 event matches our two target codes, so
                            // without this cap a chatty unrelated app could force us to scan the
                            // entire Application log history and never hit the break above.
                            if (scannedCount >= 500) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }

                rep.AppCrashes = appErrCount;
                if (faultApps.Count > 0)
                {
                    rep.AppCrashSummary = string.Format("{0} (Heap corruption / Access violation)", string.Join(", ", faultApps.ToArray()));
                }
            }
            catch { }

            // 8. OS Info (Win32_OperatingSystem: Caption, BuildNumber, 64-bit arch)
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT Caption, BuildNumber, OSArchitecture FROM Win32_OperatingSystem"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        string cap = mo["Caption"] != null ? mo["Caption"].ToString() : "Windows";
                        string build = mo["BuildNumber"] != null ? mo["BuildNumber"].ToString() : "10.0";
                        string arch = mo["OSArchitecture"] != null ? mo["OSArchitecture"].ToString() : "64-bit";
                        rep.Os = string.Format("{0} (Build {1}, {2})", cap, build, arch);
                        break;
                    }
                }
            }
            catch
            {
                rep.Os = "Microsoft Windows (64-bit)";
            }

            ReportProgress(58, "Counting crash dumps...");
            // 9. MiniDump Check (%SystemRoot%\Minidump: count + latest timestamp).
            // Folder ACL is Administrators/SYSTEM only on default installs, so a standard user gets
            // UnauthorizedAccessException. Report that state instead of a false "none detected".
            try
            {
                string winDir = Environment.GetEnvironmentVariable("SystemRoot");
                if (string.IsNullOrEmpty(winDir)) winDir = @"C:\Windows";
                string dumpDir = System.IO.Path.Combine(winDir, "Minidump");
                if (Directory.Exists(dumpDir))
                {
                    string[] files = Directory.GetFiles(dumpDir, "*.dmp");
                    rep.MiniDumpCount = files.Length;
                    if (files.Length > 0)
                    {
                        DateTime latestTime = DateTime.MinValue;
                        string latestFile = "";
                        foreach (string f in files)
                        {
                            try
                            {
                                DateTime wt = File.GetLastWriteTime(f);
                                if (wt > latestTime)
                                {
                                    latestTime = wt;
                                    latestFile = System.IO.Path.GetFileName(f);
                                }
                            }
                            catch { }
                        }
                        if (string.IsNullOrEmpty(latestFile))
                        {
                            Array.Sort(files);
                            latestFile = System.IO.Path.GetFileName(files[files.Length - 1]);
                        }
                        rep.MiniDumpLatestTime = latestTime;
                        rep.MiniDumpSummary = latestTime > DateTime.MinValue
                            ? string.Format("{0} dump files, latest {1} @ {2:yyyy-MM-dd HH:mm:ss}", files.Length, latestFile, latestTime)
                            : string.Format("{0} dump files, latest {1}", files.Length, latestFile);
                    }
                }
            }
            catch (UnauthorizedAccessException)
            {
                rep.MiniDumpSummary = "Access denied (run as Administrator to read crash dumps)";
            }
            catch (IOException ex)
            {
                rep.MiniDumpSummary = "Unreadable (" + ex.Message + ")";
            }
            catch { }

            // 10. Chassis & Battery Detection
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT ChassisTypes FROM Win32_SystemEnclosure"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        if (mo["ChassisTypes"] != null)
                        {
                            ushort[] types = mo["ChassisTypes"] as ushort[];
                            if (types == null && mo["ChassisTypes"] is Array)
                            {
                                Array arr = (Array)mo["ChassisTypes"];
                                if (arr.Length > 0)
                                {
                                    int tVal = Convert.ToInt32(arr.GetValue(0));
                                    types = new ushort[] { (ushort)tVal };
                                }
                            }
                            if (types != null && types.Length > 0)
                            {
                                ushort t = types[0];
                                if (t == 3 || t == 4 || t == 6 || t == 7) rep.ChassisType = "Desktop PC";
                                else if (t == 8 || t == 9 || t == 10 || t == 14) rep.ChassisType = "Laptop / Notebook";
                                else if (t == 11) rep.ChassisType = "Handheld";
                                else if (t == 13) rep.ChassisType = "All-in-One";
                                else if (t == 23) rep.ChassisType = "Rack Server";
                                else rep.ChassisType = "PC Chassis (" + t + ")";
                            }
                        }
                        break;
                    }
                }
            }
            catch { }

            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher("SELECT EstimatedChargeRemaining, BatteryStatus FROM Win32_Battery"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        rep.HasBattery = true;
                        int charge = 0;
                        if (mo["EstimatedChargeRemaining"] != null) int.TryParse(mo["EstimatedChargeRemaining"].ToString(), out charge);
                        int status = 0;
                        if (mo["BatteryStatus"] != null) int.TryParse(mo["BatteryStatus"].ToString(), out status);
                        string statusStr = "Normal";
                        if (status == 1) statusStr = "Discharging";
                        else if (status == 2) statusStr = "AC Connected";
                        else if (status == 3) statusStr = "Fully Charged";
                        else if (status == 4) statusStr = "Low Battery";
                        else if (status == 5) statusStr = "Critical Battery";
                        else if (status == 6) statusStr = "Charging";
                        else if (status == 7) statusStr = "Charging";
                        else if (status == 8) statusStr = "Charging (Low)";
                        else if (status == 9) statusStr = "Charging (Critical)";
                        
                        rep.BatterySummary = string.Format("{0}% ({1})", charge, statusStr);
                        break;
                    }
                }
            }
            catch { }

            ReportProgress(64, "Scanning WHEA, BSOD & TDR events...");
            // 11. WHEA Machine Check Errors (Event 18/19/47 from Microsoft-Windows-WHEA-Logger)
            try
            {
                string wheaQuery = "*[System[Provider[@Name='Microsoft-Windows-WHEA-Logger'] and (EventID=18 or EventID=19 or EventID=47)]]";
                EventLogQuery queryWhea = new EventLogQuery("System", PathType.LogName, wheaQuery);
                queryWhea.ReverseDirection = true;

                int wheaCount = 0;
                int wheaRecent = 0;
                string latestWheaMsg = "";
                long latestWheaRecId = 0;
                DateTime latestWheaTime = DateTime.MinValue;

                using (EventLogReader reader = new EventLogReader(queryWhea))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            wheaCount++;
                            if (rec.TimeCreated.HasValue && rec.TimeCreated.Value >= DateTime.Now.AddDays(-7)) wheaRecent++;
                            if (wheaCount == 1)
                            {
                                try
                                {
                                    if (rec.RecordId.HasValue) latestWheaRecId = rec.RecordId.Value;
                                    if (rec.TimeCreated.HasValue) latestWheaTime = rec.TimeCreated.Value;
                                    latestWheaMsg = rec.FormatDescription();
                                }
                                catch { }
                            }
                            if (wheaCount >= 100) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }

                rep.WheaCount = wheaCount;
                rep.WheaCount7d = wheaRecent;
                rep.WheaLatestRecordId = latestWheaRecId;
                rep.WheaLatestTime = latestWheaTime;
                rep.WheaLatestMessage = latestWheaMsg;
                if (wheaCount > 0)
                {
                    rep.WheaSummary = string.Format("{0} machine check error events", wheaCount);
                }
                else
                {
                    rep.WheaSummary = "None detected";
                }
            }
            catch { }

            // 12. Windows BugCheck BSOD (Event 1001)
            try
            {
                string bcQuery = "*[System[(Provider[@Name='Microsoft-Windows-WER-SystemErrorReporting'] or Provider[@Name='BugCheck']) and EventID=1001]]";
                EventLogQuery queryBc = new EventLogQuery("System", PathType.LogName, bcQuery);
                queryBc.ReverseDirection = true;

                int bcCount = 0;
                string stopCode = "";
                DateTime bcLatestTime = DateTime.MinValue;
                string bcDesc = "";

                using (EventLogReader reader = new EventLogReader(queryBc))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            bcCount++;
                            if (bcCount == 1)
                            {
                                try
                                {
                                    if (rec.TimeCreated.HasValue) bcLatestTime = rec.TimeCreated.Value;
                                    bcDesc = rec.FormatDescription();
                                    if (!string.IsNullOrEmpty(bcDesc))
                                    {
                                        Match mSc = Regex.Match(bcDesc, @"(0x[0-9a-fA-F]{8})");
                                        if (mSc.Success)
                                        {
                                            stopCode = mSc.Groups[1].Value.ToUpper();
                                        }
                                    }
                                }
                                catch { }
                            }
                            if (bcCount >= 50) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }

                rep.BugCheckCount = bcCount;
                rep.BugCheckLatestTime = bcLatestTime;
                if (!string.IsNullOrEmpty(stopCode))
                {
                    string friendlyName = stopCode;
                    uint scVal;
                    if (uint.TryParse(stopCode.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out scVal))
                    {
                        friendlyName = DecodeStopCode(scVal);
                    }
                    rep.BugCheckStopCode = friendlyName;
                    rep.BugCheckSummary = string.Format("{0} ({1} recorded)", friendlyName, bcCount);
                }
                else if (bcCount > 0)
                {
                    rep.BugCheckSummary = string.Format("{0} crashes recorded", bcCount);
                }
                else
                {
                    rep.BugCheckSummary = "None detected";
                }
            }
            catch { }

            // 13. Display Driver Resets (TDR Event 4101 from Display provider)
            try
            {
                string tdrQuery = "*[System[Provider[@Name='Display'] and EventID=4101]]";
                EventLogQuery queryTdr = new EventLogQuery("System", PathType.LogName, tdrQuery);
                queryTdr.ReverseDirection = true;

                int tdrCount = 0;
                string tdrDriver = "";

                using (EventLogReader reader = new EventLogReader(queryTdr))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            tdrCount++;
                            if (tdrCount == 1)
                            {
                                try
                                {
                                    string desc = rec.FormatDescription();
                                    if (!string.IsNullOrEmpty(desc))
                                    {
                                        Match mDrv = Regex.Match(desc, @"driver\s+([a-zA-Z0-9_-]+)\s+stopped", RegexOptions.IgnoreCase);
                                        if (mDrv.Success)
                                        {
                                            tdrDriver = mDrv.Groups[1].Value;
                                        }
                                    }
                                }
                                catch { }
                            }
                            if (tdrCount >= 50) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }

                rep.DisplayTdrCount = tdrCount;
                if (tdrCount > 0)
                {
                    rep.DisplayTdrSummary = !string.IsNullOrEmpty(tdrDriver) 
                        ? string.Format("{0} resets ({1})", tdrCount, tdrDriver)
                        : string.Format("{0} resets", tdrCount);
                }
                else
                {
                    rep.DisplayTdrSummary = "None detected";
                }
            }
            catch { }

            ReportProgress(72, "Reading reliability index & throttle events...");
            // 14. Windows System Reliability Index (Score 1.0 to 10.0)
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
                    "SELECT SystemStabilityIndex, TimeGenerated FROM Win32_ReliabilityStabilityMetrics"))
                {
                    double latestScore = -1;
                    DateTime latestTime = DateTime.MinValue;
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        if (mo["SystemStabilityIndex"] != null)
                        {
                            double score = Convert.ToDouble(mo["SystemStabilityIndex"]);
                            DateTime tg = DateTime.MinValue;
                            if (mo["TimeGenerated"] != null)
                            {
                                try { tg = ManagementDateTimeConverter.ToDateTime(mo["TimeGenerated"].ToString()); } catch { }
                            }
                            if (tg >= latestTime || latestScore < 0)
                            {
                                latestScore = score;
                                latestTime = tg;
                            }
                        }
                    }
                    if (latestScore >= 0)
                    {
                        rep.SystemReliabilityScore = Math.Round(latestScore, 1);
                        string rating = latestScore >= 8.0 ? "Stable / Healthy" : latestScore >= 5.0 ? "Moderate Stability" : "Degraded / Unstable";
                        rep.SystemReliabilitySummary = string.Format("{0:F1} / 10.0 ({1})", rep.SystemReliabilityScore, rating);
                    }
                }
            }
            catch { }

            // 15. CPU Thermal & Firmware Throttling (Kernel-Processor-Power Event 37)
            try
            {
                string throttleQuery = "*[System[Provider[@Name='Microsoft-Windows-Kernel-Processor-Power'] and EventID=37]]";
                EventLogQuery queryThrottle = new EventLogQuery("System", PathType.LogName, throttleQuery);
                queryThrottle.ReverseDirection = true;
                int tCount = 0;
                using (EventLogReader reader = new EventLogReader(queryThrottle))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            tCount++;
                            if (tCount == 1 && rec.TimeCreated.HasValue)
                            {
                                rep.LatestThrottleTime = rec.TimeCreated.Value;
                            }
                            if (tCount >= 100) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }
                rep.CpuThrottleCount = tCount;
            }
            catch { }

            ReportProgress(78, "Checking Device Manager faults & memory diagnostics...");
            // 16. Device Manager Hardware Errors (Win32_PnPEntity ConfigManagerErrorCode != 0)
            // Codes 22 (user-disabled in Device Manager) and 24 (device not currently present/
            // connected) are excluded: both are normal, healthy states, not hardware faults.
            // Including them would false-flag any PC where someone simply turned off an unused
            // adapter, or has a docking-station device that's currently unplugged.
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
                    "SELECT Name, ConfigManagerErrorCode, DeviceID FROM Win32_PnPEntity WHERE ConfigManagerErrorCode <> 0 AND ConfigManagerErrorCode <> 22 AND ConfigManagerErrorCode <> 24"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        string name = mo["Name"] != null ? mo["Name"].ToString().Trim() : "Unknown Device";
                        int code = mo["ConfigManagerErrorCode"] != null ? Convert.ToInt32(mo["ConfigManagerErrorCode"]) : 0;
                        string desc = string.Format("Code {0}", code);
                        if (code == 43) desc = "Code 43 (Device Problem / VRAM Failure)";
                        else if (code == 10) desc = "Code 10 (Device Cannot Start)";
                        else if (code == 28) desc = "Code 28 (Drivers Missing)";
                        else if (code == 12) desc = "Code 12 (Resource Conflict)";
                        else if (code == 14) desc = "Code 14 (Reboot Required)";
                        rep.PnpDeviceErrors.Add(string.Format("{0} [{1}]", name, desc));
                        if (rep.PnpDeviceErrors.Count >= 10) break;
                    }
                }
            }
            catch { }

            // 17. Windows Memory Diagnostic Results (Event 1101 = Pass, 1201 = Hardware Fault)
            try
            {
                string memQuery = "*[System[Provider[@Name='Microsoft-Windows-MemoryDiagnostics-Results'] and (EventID=1101 or EventID=1201)]]";
                EventLogQuery queryMem = new EventLogQuery("System", PathType.LogName, memQuery);
                queryMem.ReverseDirection = true;
                using (EventLogReader reader = new EventLogReader(queryMem))
                {
                    EventRecord rec = reader.ReadEvent();
                    if (rec != null)
                    {
                        try
                        {
                            rep.MemDiagRan = true;
                            rep.MemDiagFailed = (rec.Id == 1201);
                            if (rec.TimeCreated.HasValue) rep.MemDiagLatestTime = rec.TimeCreated.Value;
                        }
                        finally { rec.Dispose(); }
                    }
                }
            }
            catch { }

            // 18. Low Virtual Memory Exhaustion (Resource-Exhaustion-Detector Event 2004)
            try
            {
                string lowMemQuery = "*[System[Provider[@Name='Microsoft-Windows-Resource-Exhaustion-Detector'] and EventID=2004]]";
                EventLogQuery queryLowMem = new EventLogQuery("System", PathType.LogName, lowMemQuery);
                queryLowMem.ReverseDirection = true;
                int lmCount = 0;
                string topLeaker = "";
                using (EventLogReader reader = new EventLogReader(queryLowMem))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            lmCount++;
                            if (lmCount == 1)
                            {
                                try
                                {
                                    string desc = rec.FormatDescription();
                                    if (!string.IsNullOrEmpty(desc))
                                    {
                                        Match mProc = Regex.Match(desc, @"([a-zA-Z0-9_\-\.]+\.exe)\s*\([0-9]+\)\s*consumed\s*([0-9]+)\s*bytes", RegexOptions.IgnoreCase);
                                        if (mProc.Success)
                                        {
                                            long bytes;
                                            if (long.TryParse(mProc.Groups[2].Value, out bytes))
                                            {
                                                topLeaker = string.Format("{0} ({1:F1} GB)", mProc.Groups[1].Value, bytes / (1024.0 * 1024.0 * 1024.0));
                                            }
                                        }
                                    }
                                }
                                catch { }
                            }
                            if (lmCount >= 20) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }
                rep.LowMemoryEvents = lmCount;
                rep.LowMemorySummary = !string.IsNullOrEmpty(topLeaker) ? topLeaker : (lmCount > 0 ? "Memory leak events recorded" : "None detected");
            }
            catch { }

            // 19. Dead CMOS Battery RTC Clock Drift (Kernel-General Event 1)
            // Real message text is "The system time has changed to <to> from <from>." - verified
            // against real event samples, it never contains "jumped" or "backward", so a keyword
            // search for those words never matches anything. A dead coin-cell battery shows up
            // differently: on cold boot the BIOS falls back to a hardcoded default date (commonly
            // 2001 or earlier), so we check the "from" timestamp for that instead - the actual
            // dead-battery signature, rather than any ordinary NTP time correction.
            try
            {
                string rtcQuery = "*[System[Provider[@Name='Microsoft-Windows-Kernel-General'] and EventID=1]]";
                EventLogQuery queryRtc = new EventLogQuery("System", PathType.LogName, rtcQuery);
                queryRtc.ReverseDirection = true;
                using (EventLogReader reader = new EventLogReader(queryRtc))
                {
                    int checkedCount = 0;
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            checkedCount++;
                            try
                            {
                                string desc = rec.FormatDescription();
                                Match m = Regex.Match(desc ?? "", @"from\s+(\d{4})-\d{2}-\d{2}T");
                                if (m.Success)
                                {
                                    int fromYear;
                                    if (int.TryParse(m.Groups[1].Value, out fromYear) && fromYear <= 2001)
                                    {
                                        rep.CmosClockDriftDetected = true;
                                        break;
                                    }
                                }
                            }
                            catch { }
                            if (checkedCount >= 50) break; // this event fires on every NTP sync too; cap the scan
                        }
                        finally { rec.Dispose(); }
                    }
                }
            }
            catch { }

            // NOTE: A "USB Port Overcurrent (USB-USBHUB Event 11)" check was here and has been
            // removed. Event ID 11 in the System log is well-documented as the "disk" source
            // controller-error event (same family as the existing bad-block checks above) and
            // fires routinely for ordinary flaky USB flash drives - it is NOT a confirmed
            // electrical-overcurrent event from the USB-USBHUB provider. Shipping it as written
            // risked mislabeling a harmless flash-drive hiccup as "USB port overcurrent / short
            // circuit," which is exactly the kind of false, alarming claim this scanner is trying
            // to stop making. Re-add only once the real provider/EventID pair is confirmed by
            // reproducing an actual overcurrent condition and checking Event Viewer directly.

            // 21. Dead Essential Automatic Services (Win32_Service Auto + Stopped)
            try
            {
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(
                    "SELECT Name, DisplayName FROM Win32_Service WHERE StartMode = 'Auto' AND State <> 'Running'"))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        string name = mo["Name"] != null ? mo["Name"].ToString() : "";
                        string disp = mo["DisplayName"] != null ? mo["DisplayName"].ToString() : name;
                        if (name.Equals("AudioSrv", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("AudioEndpointBuilder", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("Spooler", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("BITS", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("EventLog", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("wuauserv", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("CryptSvc", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("Dhcp", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("Dnscache", StringComparison.OrdinalIgnoreCase) ||
                            name.Equals("LanmanWorkstation", StringComparison.OrdinalIgnoreCase))
                        {
                            rep.DeadAutoServices.Add(string.Format("{0} ({1})", disp, name));
                        }
                    }
                }
            }
            catch { }

            ReportProgress(86, "Checking TPM, Secure Boot & BitLocker...");
            // 22. TPM 2.0 & Secure Boot Status
            try
            {
                ManagementScope tpmScope = new ManagementScope(@"root\CIMV2\Security\MicrosoftTpm");
                tpmScope.Options = new ConnectionOptions();
                tpmScope.Options.Timeout = _wmiTimeout;
                tpmScope.Connect();
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(tpmScope,
                    new ObjectQuery("SELECT IsActivated_InitialValue, IsEnabled_InitialValue, SpecVersion FROM Win32_Tpm")))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        string spec = mo["SpecVersion"] != null ? mo["SpecVersion"].ToString() : "2.0";
                        bool enabled = mo["IsEnabled_InitialValue"] != null && Convert.ToBoolean(mo["IsEnabled_InitialValue"]);
                        bool activated = mo["IsActivated_InitialValue"] != null && Convert.ToBoolean(mo["IsActivated_InitialValue"]);
                        rep.TpmStatus = string.Format("TPM {0} ({1})", spec, (enabled && activated) ? "Ready & Enabled" : "Present but Disabled");
                        break;
                    }
                }
            }
            catch
            {
                rep.TpmStatus = "Not detected / Needs Admin";
            }

            try
            {
                object sbVal = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled", null);
                if (sbVal != null)
                {
                    rep.SecureBootStatus = Convert.ToInt32(sbVal) == 1 ? "Enabled" : "Disabled";
                }
                else
                {
                    rep.SecureBootStatus = "Unsupported / Legacy BIOS";
                }
            }
            catch
            {
                rep.SecureBootStatus = "Unknown";
            }

            // 23. BitLocker & SSD TRIM Status
            try
            {
                ManagementScope bScope = new ManagementScope(@"root\CIMV2\Security\MicrosoftVolumeEncryption");
                bScope.Options = new ConnectionOptions();
                bScope.Options.Timeout = _wmiTimeout;
                bScope.Connect();
                using (ManagementObjectSearcher mos = new ManagementObjectSearcher(bScope,
                    new ObjectQuery("SELECT DriveLetter, ProtectionStatus FROM Win32_EncryptableVolume WHERE DriveLetter = 'C:'")))
                {
                    foreach (ManagementObject mo in WmiGet(mos))
                    {
                        uint prot = mo["ProtectionStatus"] != null ? Convert.ToUInt32(mo["ProtectionStatus"]) : 0;
                        rep.BitLockerStatus = (prot == 1) ? "BitLocker Protected" : "BitLocker Off";
                        break;
                    }
                }
            }
            catch
            {
                rep.BitLockerStatus = "Unencrypted (or Non-Elevated)";
            }

            try
            {
                object regVal = Registry.GetValue(
                    @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem", "NtfsDisableDeleteNotify", null);
                if (regVal == null)
                {
                    regVal = Registry.GetValue(
                        @"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\FileSystem", "DisableDeleteNotify", 0);
                }
                rep.SsdTrimEnabled = (regVal != null && Convert.ToInt32(regVal) == 0);
            }
            catch { }

            // 24. NTFS File System Corruption (Event 55/98)
            try
            {
                string ntfsQuery = "*[System[Provider[@Name='Microsoft-Windows-Ntfs'] and (EventID=55 or EventID=98)]]";
                EventLogQuery queryNtfs = new EventLogQuery("System", PathType.LogName, ntfsQuery);
                queryNtfs.ReverseDirection = true;
                int ntfsCount = 0;
                using (EventLogReader reader = new EventLogReader(queryNtfs))
                {
                    for (EventRecord rec = reader.ReadEvent(); rec != null; rec = reader.ReadEvent())
                    {
                        try
                        {
                            ntfsCount++;
                            if (ntfsCount >= 20) break;
                        }
                        finally { rec.Dispose(); }
                    }
                }
                rep.NtfsCorruptionEvents = ntfsCount;
            }
            catch { }

            ReportProgress(94, "Reading battery & network counters...");
            // 25. Battery Wear Level & Cycle Count
            if (rep.HasBattery)
            {
                try
                {
                    ManagementScope bScope = new ManagementScope(@"root\WMI");
                    bScope.Options = new ConnectionOptions();
                    bScope.Options.Timeout = _wmiTimeout;
                    bScope.Connect();
                    int designCap = 0, fullCap = 0, cycles = 0;
                    using (ManagementObjectSearcher mos = new ManagementObjectSearcher(bScope, new ObjectQuery("SELECT DesignedCapacity FROM BatteryStaticData")))
                    {
                        foreach (ManagementObject mo in WmiGet(mos))
                        {
                            if (mo["DesignedCapacity"] != null) { designCap = Convert.ToInt32(mo["DesignedCapacity"]); break; }
                        }
                    }
                    using (ManagementObjectSearcher mos = new ManagementObjectSearcher(bScope, new ObjectQuery("SELECT FullChargedCapacity FROM BatteryFullChargedCapacity")))
                    {
                        foreach (ManagementObject mo in WmiGet(mos))
                        {
                            if (mo["FullChargedCapacity"] != null) { fullCap = Convert.ToInt32(mo["FullChargedCapacity"]); break; }
                        }
                    }
                    using (ManagementObjectSearcher mos = new ManagementObjectSearcher(bScope, new ObjectQuery("SELECT CycleCount FROM BatteryCycleCount")))
                    {
                        foreach (ManagementObject mo in WmiGet(mos))
                        {
                            if (mo["CycleCount"] != null) { cycles = Convert.ToInt32(mo["CycleCount"]); break; }
                        }
                    }
                    if (designCap > 0 && fullCap > 0 && fullCap < designCap)
                    {
                        rep.BatteryWearPercent = Math.Round((1.0 - ((double)fullCap / designCap)) * 100.0, 1);
                    }
                    rep.BatteryCycleCount = cycles;
                }
                catch { }
            }

            // 26. Network Adapter Packet Errors & Discards
            try
            {
                long pErr = 0;
                long pDisc = 0;
                foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.OperationalStatus == OperationalStatus.Up &&
                        nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    {
                        IPv4InterfaceStatistics s = nic.GetIPv4Statistics();
                        pErr += s.IncomingPacketsWithErrors + s.OutgoingPacketsWithErrors;
                        pDisc += s.IncomingPacketsDiscarded + s.OutgoingPacketsDiscarded;
                    }
                }
                rep.NetworkPacketErrors = pErr;
                rep.NetworkPacketDiscards = pDisc;
            }
            catch { }

            try { rep.CalculatePcfixScore(); } catch { }
            return rep;
        }

        // Many boards echo the JEDEC speed into SMBIOS Speed, hiding the XMP/EXPO rating.
        // Recover the kit rating from the vendor part number. Returns 0 when no pattern matches.
        //   Kingston Fury  KF3200C16D4/16GX, KF560C36BBE-16  (3-digit DDR5 form = x10)
        //   Corsair        CMK32GX4M2D3600C18, CMH32GX5M2B6000C30
        //   G.Skill        F4-3600C16D-32GVKC, F5-6000J3038F16GX2
        //   Crucial        BL2K16G36C16U4B (Ballistix), CP2K16G4DFRA32A
        //   TeamGroup      TF3D432G3600HC18JDC01
        private static uint ParseRatedSpeedFromPartNumber(string part)
        {
            if (string.IsNullOrEmpty(part)) return 0;
            string p = part.Trim().ToUpperInvariant();
            Match m;
            try
            {
                uint v;
                m = Regex.Match(p, @"^KF(\d{3,4})C");
                if (m.Success)
                {
                    if (!uint.TryParse(m.Groups[1].Value, out v)) return 0;
                    if (v < 1000) v *= 10;
                    return SaneDdrSpeed(v);
                }
                m = Regex.Match(p, @"^CM[A-Z]{1,4}\d+GX[45]M\d[A-Z](\d{4})");
                if (m.Success)
                {
                    if (!uint.TryParse(m.Groups[1].Value, out v)) return 0;
                    return SaneDdrSpeed(v);
                }
                m = Regex.Match(p, @"^F[45]-(\d{4})[A-Z]");
                if (m.Success)
                {
                    if (!uint.TryParse(m.Groups[1].Value, out v)) return 0;
                    return SaneDdrSpeed(v);
                }
                m = Regex.Match(p, @"^BL\d*K?\d+G(\d{2})C\d");
                if (m.Success)
                {
                    if (!uint.TryParse(m.Groups[1].Value, out v)) return 0;
                    return SaneDdrSpeed(v * 100);
                }
                m = Regex.Match(p, @"^T[A-Z0-9]{2,5}\d+G(\d{4})HC");
                if (m.Success)
                {
                    if (!uint.TryParse(m.Groups[1].Value, out v)) return 0;
                    return SaneDdrSpeed(v);
                }
            }
            catch { }
            return 0;
        }

        private static uint SaneDdrSpeed(uint v)
        {
            return (v >= 1600 && v <= 10000) ? v : 0;
        }

        // Reads a named <Data> field from an event's XML payload. Falls back to positional Properties[]
        // when the XML read fails. Accepts decimal or 0x-prefixed hex. Returns 0 on any failure.
        private static uint ExtractEventDataUInt(EventRecord rec, string fieldName, int fallbackIndex)
        {
            string raw = null;
            try
            {
                string xml = rec.ToXml();
                Match m = Regex.Match(xml, "<Data Name=['\"]" + Regex.Escape(fieldName) + "['\"]>([^<]*)</Data>", RegexOptions.IgnoreCase);
                if (m.Success) raw = m.Groups[1].Value.Trim();
            }
            catch { }

            if (raw == null)
            {
                try
                {
                    if (rec.Properties != null && rec.Properties.Count > fallbackIndex && rec.Properties[fallbackIndex].Value != null)
                        raw = rec.Properties[fallbackIndex].Value.ToString().Trim();
                }
                catch { }
            }
            if (string.IsNullOrEmpty(raw)) return 0;

            uint val;
            if (raw.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (uint.TryParse(raw.Substring(2), System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out val)) return val;
                return 0;
            }
            ulong wide;
            if (ulong.TryParse(raw, System.Globalization.NumberStyles.Integer, System.Globalization.CultureInfo.InvariantCulture, out wide)) return (uint)(wide & 0xFFFFFFFF);
            return 0;
        }

        // Human-readable stop code. Output format "0x124 (WHEA_UNCORRECTABLE_ERROR: hardware fault)".
        // HasCriticalHardwareFailure matches on the "0x124" / "0x7A" prefix, keep that format stable.
        public static string DecodeStopCode(uint code)
        {
            string hex = string.Format("0x{0:X}", code);
            string name;
            switch (code)
            {
                case 0x124: name = "WHEA_UNCORRECTABLE_ERROR: CPU, RAM or PCIe hardware fault"; break;
                case 0x9F: name = "DRIVER_POWER_STATE_FAILURE: driver failed sleep/wake transition"; break;
                case 0x133: name = "DPC_WATCHDOG_VIOLATION: driver or storage firmware stalled the CPU"; break;
                case 0x1A: name = "MEMORY_MANAGEMENT: RAM instability or corrupt page tables"; break;
                case 0x7A: name = "KERNEL_DATA_INPAGE_ERROR: page file read failed (disk or cable)"; break;
                case 0x77: name = "KERNEL_STACK_INPAGE_ERROR: page file read failed (disk)"; break;
                case 0xD1: name = "DRIVER_IRQL_NOT_LESS_OR_EQUAL: faulty driver"; break;
                case 0x0A: name = "IRQL_NOT_LESS_OR_EQUAL: faulty driver or RAM"; break;
                case 0x3B: name = "SYSTEM_SERVICE_EXCEPTION: driver or system file fault"; break;
                case 0x1E: name = "KMODE_EXCEPTION_NOT_HANDLED: driver fault"; break;
                case 0x50: name = "PAGE_FAULT_IN_NONPAGED_AREA: RAM or driver fault"; break;
                case 0xBE: name = "ATTEMPTED_WRITE_TO_READONLY_MEMORY: driver fault"; break;
                case 0x139: name = "KERNEL_SECURITY_CHECK_FAILURE: corrupt kernel structure"; break;
                case 0x10A: name = "KERNEL_MODE_HEAP_CORRUPTION: driver fault"; break;
                case 0x101: name = "CLOCK_WATCHDOG_TIMEOUT: CPU core hang (overclock or voltage)"; break;
                case 0x116: name = "VIDEO_TDR_FAILURE: GPU failed to recover from timeout"; break;
                case 0x117: name = "VIDEO_TDR_TIMEOUT_DETECTED: GPU timeout"; break;
                case 0xEF: name = "CRITICAL_PROCESS_DIED: system process crashed (disk or file corruption)"; break;
                case 0xF4: name = "CRITICAL_OBJECT_TERMINATION: storage device dropped"; break;
                case 0x7E: name = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED: driver fault"; break;
                case 0xC2: name = "BAD_POOL_CALLER: driver fault"; break;
                case 0x19: name = "BAD_POOL_HEADER: driver or RAM fault"; break;
                case 0x154: name = "UNEXPECTED_STORE_EXCEPTION: storage or RAM fault"; break;
                case 0x1000007E: name = "SYSTEM_THREAD_EXCEPTION_NOT_HANDLED_M: driver fault"; break;
                case 0x1000008E: name = "KERNEL_MODE_EXCEPTION_NOT_HANDLED_M: driver fault"; break;
                default: name = "see Microsoft bug check reference"; break;
            }
            return string.Format("{0} ({1})", hex, name);
        }

        private void PopulateResults(HardwareReport r)
        {
            // Update System & Motherboard Strip
            string boardStr = "";
            if (!string.IsNullOrEmpty(r.BoardProduct) && r.BoardProduct != "Unknown")
            {
                boardStr = string.Format("{0} {1} | BIOS {2} ({3})", r.BoardManufacturer, r.BoardProduct, r.BiosVersion, r.BootMode);
            }
            else
            {
                boardStr = string.Format("System Firmware BIOS {0} ({1})", r.BiosVersion, r.BootMode);
            }

            if (r.HasBattery && !string.IsNullOrEmpty(r.BatterySummary))
            {
                boardStr += string.Format(" | Battery: {0}", r.BatterySummary);
            }
            else if (!string.IsNullOrEmpty(r.ChassisType) && r.ChassisType != "Unknown")
            {
                boardStr += string.Format(" | {0}", r.ChassisType);
            }

            if (_sysInfoText != null) _sysInfoText.Text = boardStr;
            if (_osInfoText != null) _osInfoText.Text = !string.IsNullOrEmpty(r.Os) ? r.Os : "Microsoft Windows (64-bit)";

            // Phase 3: Update score badge colors (4-tier scale)
            if (_scoreBadge != null && _scoreBadgeText != null)
            {
                SolidColorBrush badgeColor = r.PcfixScore >= 85 ? _colorOk : (r.PcfixScore >= 65 ? _colorWarn : (r.PcfixScore >= 45 ? _colorDegraded : _colorCritical));
                _scoreBadgeText.Foreground = badgeColor;
                _scoreBadgeText.Text = string.Format("pcfix Score: {0}/100 ({1})", r.PcfixScore, r.PcfixScoreLabel);
                _scoreBadge.Background = new SolidColorBrush(Color.FromArgb(25, badgeColor.Color.R, badgeColor.Color.G, badgeColor.Color.B));
                _scoreBadge.BorderBrush = new SolidColorBrush(Color.FromArgb(70, badgeColor.Color.R, badgeColor.Color.G, badgeColor.Color.B));
                _scoreBadge.BorderThickness = new Thickness(1);
            }


            // Update Matrix Cards
            _cpuTitle.Text = !string.IsNullOrEmpty(r.CpuName) ? r.CpuName : r.Cpu;
            _cpuSub.Text = !string.IsNullOrEmpty(r.CpuDetail) ? r.CpuDetail : "Processor detected";
            _cpuSub.Foreground = _colorOk;

            _gpuTitle.Text = !string.IsNullOrEmpty(r.GpuName) ? r.GpuName : r.Gpu;
            _gpuSub.Text = !string.IsNullOrEmpty(r.GpuDetail) ? r.GpuDetail : "Active Display Driver";
            _gpuSub.Foreground = _colorOk;

            _ramTitle.Text = !string.IsNullOrEmpty(r.RamName) ? r.RamName : r.Ram;
            _ramSub.Text = !string.IsNullOrEmpty(r.RamDetail) ? r.RamDetail : "System Memory";
            _ramSub.Foreground = _colorOk;

            _storageTitle.Text = !string.IsNullOrEmpty(r.StorageName) ? r.StorageName : r.StorageSummary;
            if (r.Disks.Exists(d => d.IsSsdDeath))
            {
                _storageSub.Text = "SMART Failure | Critical";
                _storageSub.Foreground = _colorCritical;
            }
            else if (r.BadBlockTotal > 0)
            {
                _storageSub.Text = string.Format("{0:N0} Read Retries | Maintenance", r.BadBlockTotal);
                _storageSub.Foreground = _colorDegraded;
            }
            else if (r.Disks.Exists(d => d.Status != "OK" || d.SmartHealthStatus == "Warning"))
            {
                _storageSub.Text = "Drive Warning | SMART Check";
                _storageSub.Foreground = _colorWarn;
            }
            else
            {
                _storageSub.Text = !string.IsNullOrEmpty(r.StorageDetail) ? r.StorageDetail : string.Format("{0} Disks (SMART Unavailable)", r.Disks.Count);
                _storageSub.Foreground = _colorOk;
            }

            // Status Alert Card (three-tier severity)
            if (r.HasTier1HardwareFault)
            {
                _alertCard.Background = new SolidColorBrush(Color.FromArgb(40, 248, 81, 73));
                _alertCard.BorderBrush = _colorCritical;
                _alertIconBox.Background = new SolidColorBrush(Color.FromArgb(50, 248, 81, 73));
                _alertIconText.Foreground = _colorCritical;
                _alertIconText.Text = "✕";

                List<string> failureReasons = new List<string>();
                List<string> failureDetails = new List<string>();

                if (r.WheaCount > 0)
                {
                    failureReasons.Add(string.Format("{0} WHEA Hardware Errors", r.WheaCount));
                    failureDetails.Add(string.Format("Windows Hardware Error Architecture (WHEA) logged uncorrectable machine check events ({0}). Processor or system bus instability indicated.", r.WheaSummary));
                }

                if (r.MemDiagFailed)
                {
                    failureReasons.Add("RAM Hardware Fault");
                    failureDetails.Add("Windows Memory Diagnostic confirmed defective physical DRAM.");
                }

                if (!string.IsNullOrEmpty(r.KernelPowerStopCode) && (r.KernelPowerStopCode.IndexOf("0x124", StringComparison.OrdinalIgnoreCase) >= 0 || r.KernelPowerStopCode.IndexOf("0x7A", StringComparison.OrdinalIgnoreCase) >= 0 || r.KernelPowerStopCode.IndexOf("0x1A", StringComparison.OrdinalIgnoreCase) >= 0))
                {
                    failureReasons.Add("Critical BSOD (" + r.KernelPowerStopCode + ")");
                    failureDetails.Add("System crashed with critical kernel stop code: " + r.KernelPowerStopCode + ".");
                }

                foreach (DiskItem d in r.Disks)
                {
                    if (d.IsSsdDeath)
                    {
                        failureReasons.Add(string.Format("Disk {0} SSD Failure", d.Index));
                        failureDetails.Add(string.Format("Drive {0} ({1}) reports severe wear or predictive failure. Replace the drive.", d.Index, d.Model));
                    }
                }

                _alertHeading.Text = "CRITICAL HARDWARE FAILURE DETECTED";
                _alertHeading.Foreground = _colorCritical;
                _alertDesc.Text = string.Join(" ", failureDetails.ToArray()) + " Replace defective component before total failure. Back up critical personal files immediately.";
            }
            else if (r.HasTier2Maintenance)
            {
                _alertCard.Background = new SolidColorBrush(Color.FromArgb(30, 219, 109, 40));
                _alertCard.BorderBrush = _colorDegraded;
                _alertIconBox.Background = new SolidColorBrush(Color.FromArgb(50, 219, 109, 40));
                _alertIconText.Foreground = _colorDegraded;
                _alertIconText.Text = "!";
                _alertHeading.Text = r.VerdictLabel;
                _alertHeading.Foreground = _colorDegraded;

                List<string> warnDetails = new List<string>();
                if (r.BadBlockTotal > 0)
                {
                    warnDetails.Add(string.Format("{0:N0} bad block read retries logged on {1}. File corruption or isolated bad sectors. Run chkdsk /r and back up the affected partition.", r.BadBlockTotal, r.BadBlockTargetDevice));
                }
                if (r.CpuThrottleCount > 0)
                {
                    warnDetails.Add(string.Format("CPU thermal/firmware throttling logged ({0} times). Clean cooler heatsink or re-apply thermal paste.", r.CpuThrottleCount));
                }
                if (r.DisplayTdrCount > 0)
                {
                    warnDetails.Add(string.Format("{0} display driver resets (TDR Event 4101: {1}). Clean reinstall the GPU driver using DDU.", r.DisplayTdrCount, r.DisplayTdrSummary));
                }
                if (r.NtfsCorruptionEvents > 0)
                {
                    warnDetails.Add("NTFS volume directory corruption logged. Run chkdsk.");
                }

                _alertDesc.Text = warnDetails.Count > 0 ? string.Join(" ", warnDetails.ToArray()) : "Maintenance recommended.";
            }
            else
            {
                _alertCard.Background = new SolidColorBrush(Color.FromArgb(30, 63, 185, 80));
                _alertCard.BorderBrush = _colorOk;
                _alertIconBox.Background = new SolidColorBrush(Color.FromArgb(50, 63, 185, 80));
                _alertIconText.Foreground = _colorOk;
                _alertIconText.Text = "✓";
                _alertHeading.Text = string.IsNullOrEmpty(r.VerdictLabel) ? "System Nominal - All Hardware Checks Passed" : r.VerdictLabel;
                _alertHeading.Foreground = _colorOk;
                _alertDesc.Text = string.IsNullOrEmpty(r.VerdictAdvice) ? "Zero WHEA faults, zero RAM failures, no SSD death, and normal drive SMART health verified." : r.VerdictAdvice;
            }

            _disksContainer.Children.Clear();
            foreach (DiskItem d in r.Disks)
            {
                _disksContainer.Children.Add(CreateDiskAuditCard(d));
            }

            if (r.SplitBootDetected)
            {
                _disksContainer.Children.Add(CreateSplitBootWarningCard(r.SplitBootDetails));
            }

            _eventMetricsPanel.Children.Clear();
            if (r.SystemReliabilityScore >= 0)
            {
                _eventMetricsPanel.Children.Add(CreateEventRow("Windows System Stability Index:", 
                    r.SystemReliabilitySummary, 
                    r.SystemReliabilityScore >= 8.0 ? _colorOk : (r.SystemReliabilityScore >= 5.0 ? _colorWarn : _colorCritical)));
            }

            _eventMetricsPanel.Children.Add(CreateEventRow("Disk Bad Block Read Retries (Event ID 7/51/153):", 
                r.BadBlockTotal > 0 ? string.Format("{0:N0} read retries ({1})", r.BadBlockTotal, r.BadBlockTargetDevice) : "0 detected (Nominal)", 
                r.BadBlockTotal > 0 ? _colorDegraded : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("WHEA Hardware Errors (Event 18/19/47):", 
                r.WheaCount > 0 ? string.Format("{0} events ({1})", r.WheaCount, r.WheaSummary) : "0 detected (Nominal)", 
                r.WheaCount > 0 ? _colorCritical : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("CPU Thermal / Firmware Throttling (Event 37):", 
                r.CpuThrottleCount > 0 ? string.Format("{0} events logged (Clock limited)", r.CpuThrottleCount) : "0 detected (Nominal)", 
                r.CpuThrottleCount > 0 ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Windows BugCheck BSOD (Event 1001):", 
                r.BugCheckCount > 0 ? string.Format("{0} crashes ({1})", r.BugCheckCount, !string.IsNullOrEmpty(r.BugCheckStopCode) ? r.BugCheckStopCode : r.BugCheckSummary) : "0 detected (Nominal)", 
                r.BugCheckCount > 0 ? (r.BugCheckStopCode.IndexOf("0x124") >= 0 || r.BugCheckStopCode.IndexOf("0x7A") >= 0 ? _colorCritical : _colorWarn) : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Display Driver Resets (TDR 4101):", 
                r.DisplayTdrCount > 0 ? string.Format("{0} events ({1})", r.DisplayTdrCount, r.DisplayTdrSummary) : "0 detected (Nominal)", 
                r.DisplayTdrCount > 0 ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Kernel-Power Unclean Freezes (Event 41):", 
                r.KernelPowerEvents > 0 ? string.Format("{0} events (last 7 days)", r.KernelPowerEvents) : "0 detected (Nominal)", 
                r.KernelPowerEvents >= 2 ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Device Manager Hardware Faults:", 
                r.PnpDeviceErrors.Count > 0 ? string.Format("{0} device faults ({1})", r.PnpDeviceErrors.Count, string.Join(", ", r.PnpDeviceErrors.ToArray())) : "0 faults (Nominal)", 
                r.PnpDeviceErrors.Count > 0 ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Windows Memory Diagnostic:", 
                !r.MemDiagRan ? "Not run" : (r.MemDiagFailed ? "HARDWARE FAULT DETECTED" : "Passed (0 memory errors)"), 
                r.MemDiagFailed ? _colorCritical : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Low Virtual Memory (Event 2004):", 
                r.LowMemoryEvents > 0 ? string.Format("{0} OOM events ({1})", r.LowMemoryEvents, r.LowMemorySummary) : "0 detected (Nominal)", 
                r.LowMemoryEvents > 0 ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Software Stability (App Crashes, Event 1000):", 
                r.AppCrashes > 0 ? string.Format("{0} ({1})", r.AppCrashes, r.AppCrashSummary) : "0 detected (Nominal)", 
                r.AppCrashes > 0 ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Motherboard RTC Clock (CMOS Battery):", 
                r.CmosClockDriftDetected ? "DEAD CMOS BATTERY DETECTED (Clock reset)" : "Normal (Synchronized)", 
                r.CmosClockDriftDetected ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Stopped Essential Windows Services:", 
                r.DeadAutoServices.Count > 0 ? string.Format("{0} dead ({1})", r.DeadAutoServices.Count, string.Join(", ", r.DeadAutoServices.ToArray())) : "0 detected (Nominal)", 
                r.DeadAutoServices.Count > 0 ? _colorWarn : _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Security & Platform Integrity:", 
                string.Format("{0} | Secure Boot: {1} | C: {2} | TRIM: {3}", r.TpmStatus, r.SecureBootStatus, r.BitLockerStatus, r.SsdTrimEnabled ? "Enabled" : "Disabled"), 
                _colorOk));

            _eventMetricsPanel.Children.Add(CreateEventRow("Windows MiniDump Crash Archive:", 
                r.MiniDumpSummary, 
                r.MiniDumpSummary.Contains("Nominal") ? _colorOk : _colorWarn));

            _proofContainer.Children.Clear();
            _proofContainer.Children.Add(CreateProofCard(r));

            // Upgrade 3: QR handoff + memory diagnostic trigger.
            PopulateQrCard(r);
            if (_btnMemTest != null)
            {
                _btnMemTest.Visibility = r.MemDiagRan ? Visibility.Collapsed : Visibility.Visible;
            }

            _rawPayloadPreview.Text = r.ToFormattedPayload();
        }

        // Upgrade 5: launch mdsched.exe (Windows Memory Diagnostic) with UAC prompt.
        private void ScheduleMemoryDiagnostic()
        {
            try
            {
                ProcessStartInfo psi = new ProcessStartInfo
                {
                    FileName = "mdsched.exe",
                    UseShellExecute = true
                };
                Process.Start(psi);
                if (_btnMemTestText != null)
                {
                    _btnMemTestText.Text = "Scheduled. Windows will test RAM on next reboot.";
                    _btnMemTestText.Foreground = _colorOk;
                }
            }
            catch (Exception ex)
            {
                AppendLog("WARN", "Could not launch mdsched.exe: " + ex.Message);
            }
        }

        // Upgrade 3: build the QR matrix from the handoff URL and render it in the results view.
        private void PopulateQrCard(HardwareReport r)
        {
            try
            {
                if (_qrContainer == null) return;
                _qrContainer.Children.Clear();

                string url = r.BuildQrPayload();
                bool[,] matrix = MicroQrCodeRenderer.Generate(url);
                if (matrix == null) return;

                FrameworkElement qr = MicroQrCodeRenderer.Render(matrix, _textPrimary, Brushes.White, 2.5);

                TextBlock label = new TextBlock
                {
                    Text = "Scan with Phone to Keep Repair Guide Open",
                    FontSize = 11,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = _textSecondary,
                    Margin = new Thickness(2, 0, 0, 8),
                    TextWrapping = TextWrapping.Wrap
                };

                Border card = new Border
                {
                    Background = _bgCard,
                    BorderBrush = _borderLine,
                    BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(12),
                    Padding = new Thickness(14),
                    HorizontalAlignment = HorizontalAlignment.Left
                };

                StackPanel inner = new StackPanel();
                inner.Children.Add(label);

                Border qrFrame = new Border
                {
                    Background = Brushes.White,
                    Padding = new Thickness(8),
                    CornerRadius = new CornerRadius(8),
                    HorizontalAlignment = HorizontalAlignment.Left
                };
                qrFrame.Child = qr;
                inner.Children.Add(qrFrame);

                card.Child = inner;
                _qrContainer.Children.Add(card);
            }
            catch (Exception ex)
            {
                AppendLog("INFO", "QR handoff render failed: " + ex.Message);
            }
        }

        private UIElement CreateProofCard(HardwareReport r)
        {
            Border b = new Border
            {
                Background = _bgCard,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 10)
            };

            StackPanel sp = new StackPanel();

            TextBlock tag = new TextBlock
            {
                Text = "Live Windows Kernel Verification Proof (winevt/Logs/System.evtx):",
                FontSize = 11,
                FontWeight = FontWeights.Bold,
                Foreground = _textPrimary,
                Margin = new Thickness(0, 0, 0, 4)
            };
            sp.Children.Add(tag);

            string psCommand = "";
            string psLiveArgs = "";

            if (r.BadBlockTotal > 0 && r.LatestRecordId > 0)
            {
                TextBlock recInfo = new TextBlock
                {
                    Text = string.Format("Latest Storage Event: Record #{0} @ {1:yyyy-MM-dd HH:mm:ss} | Provider: disk.sys", r.LatestRecordId, r.LatestRecordTime),
                    FontSize = 10.5,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _colorCritical,
                    Margin = new Thickness(0, 0, 0, 2)
                };
                sp.Children.Add(recInfo);

                TextBlock recMsg = new TextBlock
                {
                    Text = string.Format("Kernel Msg: \"{0}\"", r.SampleEventMessage),
                    FontSize = 10.5,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _textSecondary,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 8)
                };
                sp.Children.Add(recMsg);

                psCommand = "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk'; Id=7} -MaxEvents 3 | Format-List";
                psLiveArgs = "-NoExit -Command \"Write-Host '=== LIVE WINDOWS KERNEL STORAGE EVENT PROOF ===' -ForegroundColor Cyan; Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk'; Id=7} -MaxEvents 3 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, ProviderName, Message; Write-Host 'Verified directly from winevt/Logs/System.evtx' -ForegroundColor Green\"";
            }
            else if (r.WheaCount > 0 && r.WheaLatestRecordId > 0)
            {
                TextBlock recInfo = new TextBlock
                {
                    Text = string.Format("Latest WHEA Event: Record #{0} @ {1:yyyy-MM-dd HH:mm:ss} | Provider: Microsoft-Windows-WHEA-Logger", r.WheaLatestRecordId, r.WheaLatestTime),
                    FontSize = 10.5,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _colorCritical,
                    Margin = new Thickness(0, 0, 0, 2)
                };
                sp.Children.Add(recInfo);

                TextBlock recMsg = new TextBlock
                {
                    Text = string.Format("Kernel Msg: \"{0}\"", r.WheaLatestMessage),
                    FontSize = 10.5,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _textSecondary,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 8)
                };
                sp.Children.Add(recMsg);

                psCommand = "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 3 | Format-List";
                psLiveArgs = "-NoExit -Command \"Write-Host '=== LIVE WHEA HARDWARE EVENT LOG PROOF ===' -ForegroundColor Cyan; Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'} -MaxEvents 3 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, ProviderName, Message; Write-Host 'Verified directly from winevt/Logs/System.evtx' -ForegroundColor Green\"";
            }
            else if (r.BugCheckCount > 0)
            {
                TextBlock recInfo = new TextBlock
                {
                    Text = string.Format("Latest BugCheck Event @ {0:yyyy-MM-dd HH:mm:ss} | Stop Code: {1}", r.BugCheckLatestTime, r.BugCheckStopCode),
                    FontSize = 10.5,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _colorWarn,
                    Margin = new Thickness(0, 0, 0, 2)
                };
                sp.Children.Add(recInfo);

                TextBlock recMsg = new TextBlock
                {
                    Text = string.Format("Crash Detail: \"{0}\"", r.BugCheckSummary),
                    FontSize = 10.5,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _textSecondary,
                    TextWrapping = TextWrapping.Wrap,
                    Margin = new Thickness(0, 0, 0, 8)
                };
                sp.Children.Add(recMsg);

                psCommand = "Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 3 | Format-List";
                psLiveArgs = "-NoExit -Command \"Write-Host '=== LIVE WINDOWS BUGCHECK EVENT LOG PROOF ===' -ForegroundColor Cyan; Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} -MaxEvents 3 -ErrorAction SilentlyContinue | Format-List TimeCreated, Id, Message; Write-Host 'Verified directly from winevt/Logs/System.evtx' -ForegroundColor Green\"";
            }
            else
            {
                TextBlock noErr = new TextBlock
                {
                    Text = "System Nominal: 0 hardware fault events logged in winevt/Logs/System.evtx.",
                    FontSize = 10.5,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _colorOk,
                    Margin = new Thickness(0, 0, 0, 8)
                };
                sp.Children.Add(noErr);

                psCommand = "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk'; Id=7} -MaxEvents 1 -ErrorAction SilentlyContinue";
                psLiveArgs = "-NoExit -Command \"Write-Host '=== LIVE WINDOWS HARDWARE AUDIT ===' -ForegroundColor Cyan; $e = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='disk'; Id=7} -MaxEvents 1 -ErrorAction SilentlyContinue; if (-not $e) { Write-Host 'Verified: 0 disk hardware error records found (Nominal)' -ForegroundColor Green; } else { $e | Format-List; }\"";
            }

            // Buttons: Launch Event Viewer & Copy Command & Live PowerShell
            StackPanel btnRow = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };

            Border btnEv = new Border
            {
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(9, 5, 9, 5),
                Cursor = Cursors.Hand,
                Margin = new Thickness(0, 0, 6, 0)
            };
            TextBlock btnEvText = new TextBlock
            {
                Text = "Open Event Viewer",
                FontSize = 10,
                FontWeight = FontWeights.SemiBold,
                Foreground = _accent
            };
            btnEv.Child = btnEvText;
            btnEv.MouseEnter += (s, e) => btnEv.Background = _bgSubtleHover;
            btnEv.MouseLeave += (s, e) => btnEv.Background = _bgSubtle;
            btnEv.MouseLeftButtonDown += (s, e) =>
            {
                try { Process.Start("eventvwr.msc"); } catch { }
            };
            btnRow.Children.Add(btnEv);

            Border btnPsLive = new Border
            {
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(9, 5, 9, 5),
                Cursor = Cursors.Hand,
                Margin = new Thickness(0, 0, 6, 0)
            };
            TextBlock btnPsLiveText = new TextBlock
            {
                Text = "Live Verify in PowerShell",
                FontSize = 10,
                FontWeight = FontWeights.SemiBold,
                Foreground = _colorOk
            };
            btnPsLive.Child = btnPsLiveText;
            btnPsLive.MouseEnter += (s, e) => btnPsLive.Background = _bgSubtleHover;
            btnPsLive.MouseLeave += (s, e) => btnPsLive.Background = _bgSubtle;
            string finalLiveArgs = psLiveArgs;
            btnPsLive.MouseLeftButtonDown += (s, e) =>
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = finalLiveArgs,
                        UseShellExecute = true
                    };
                    Process.Start(psi);
                }
                catch { }
            };
            btnRow.Children.Add(btnPsLive);

            Border btnPs = new Border
            {
                Background = _bgSubtle,
                BorderBrush = _borderLine,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(9, 5, 9, 5),
                Cursor = Cursors.Hand
            };
            TextBlock btnPsText = new TextBlock
            {
                Text = "Copy PS Command",
                FontSize = 10,
                FontWeight = FontWeights.SemiBold,
                Foreground = _textPrimary
            };
            btnPs.Child = btnPsText;
            btnPs.MouseEnter += (s, e) => btnPs.Background = _bgSubtleHover;
            btnPs.MouseLeave += (s, e) => btnPs.Background = _bgSubtle;
            string finalPsCmd = psCommand;
            btnPs.MouseLeftButtonDown += (s, e) =>
            {
                try
                {
                    if (SafeSetClipboardText(finalPsCmd))
                    {
                        btnPsText.Text = "Copied!";
                        btnPsText.Foreground = _colorOk;
                    }
                }
                catch { }
            };
            btnRow.Children.Add(btnPs);

            sp.Children.Add(btnRow);
            b.Child = sp;
            return b;
        }

        private UIElement CreateDiskAuditCard(DiskItem d)
        {
            SolidColorBrush accent = d.IsSsdDeath ? _colorCritical : (d.HasReadRetries ? _colorDegraded : _colorOk);
            Border b = new Border
            {
                Background = _bgCard,
                BorderBrush = d.IsSsdDeath ? _colorCritical : (d.HasReadRetries ? _colorDegraded : _borderLine),
                BorderThickness = new Thickness(d.IsSsdDeath ? 1.5 : 1),
                CornerRadius = new CornerRadius(12),
                Padding = new Thickness(12),
                Margin = new Thickness(0, 0, 0, 6)
            };

            Grid g = new Grid();
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

            StackPanel sp = new StackPanel();
            
            StackPanel titleRow = new StackPanel { Orientation = Orientation.Horizontal };
            TextBlock diskTitle = new TextBlock
            {
                Text = string.Format("Disk {0}: {1}", d.Index, d.Model),
                FontWeight = FontWeights.Bold,
                FontSize = 12,
                Foreground = _textPrimary,
                Margin = new Thickness(0, 0, 8, 0)
            };
            titleRow.Children.Add(diskTitle);

            if (d.IsWindowsOs)
            {
                titleRow.Children.Add(CreateRolePill("WINDOWS OS", _accent));
            }
            if (d.IsBootloader)
            {
                titleRow.Children.Add(CreateRolePill("EFI BOOT", _colorWarn));
            }
            sp.Children.Add(titleRow);

            string vols = d.Volumes.Count > 0 ? string.Join(", ", d.Volumes.ToArray()) : "No drive letters";
            TextBlock sub = new TextBlock
            {
                Text = string.Format("Capacity: {0:F0} GB | Volumes: {1}", d.SizeGb, vols),
                FontSize = 11,
                Foreground = _textSecondary,
                Margin = new Thickness(0, 3, 0, 0)
            };
            sp.Children.Add(sub);

            if (!string.IsNullOrEmpty(d.SerialNumber))
            {
                TextBlock sn = new TextBlock
                {
                    Text = string.Format("Hardware S/N: {0} | FW: {1}", d.SerialNumber, d.FirmwareRevision),
                    FontSize = 10,
                    FontFamily = new FontFamily("Consolas, SF Mono, monospace"),
                    Foreground = _textMuted,
                    Margin = new Thickness(0, 2, 0, 0)
                };
                sp.Children.Add(sn);
            }

            g.Children.Add(sp);
            Grid.SetColumn(sp, 0);

            Border badge = new Border
            {
                Background = d.IsSsdDeath ? new SolidColorBrush(Color.FromArgb(40, 248, 81, 73)) : (d.HasReadRetries ? new SolidColorBrush(Color.FromArgb(30, 219, 109, 40)) : new SolidColorBrush(Color.FromArgb(30, 63, 185, 80))),
                BorderBrush = accent,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(8, 3, 8, 3),
                VerticalAlignment = VerticalAlignment.Center
            };
            badge.Child = new TextBlock
            {
                Text = d.GetHealthBadge(),
                FontSize = 10.5,
                FontWeight = FontWeights.Bold,
                Foreground = accent
            };
            g.Children.Add(badge);
            Grid.SetColumn(badge, 1);

            b.Child = g;
            return b;
        }

        private UIElement CreateSplitBootWarningCard(string details)
        {
            Border b = new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(20, 88, 166, 255)),
                BorderBrush = new SolidColorBrush(Color.FromArgb(70, 88, 166, 255)),
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(10),
                Padding = new Thickness(10),
                Margin = new Thickness(0, 0, 0, 6)
            };
            StackPanel sp = new StackPanel();
            sp.Children.Add(new TextBlock
            {
                Text = "Boot Configuration Note: Split-Boot Layout",
                FontWeight = FontWeights.Bold,
                FontSize = 11,
                Foreground = _accent,
                Margin = new Thickness(0, 0, 0, 2)
            });
            sp.Children.Add(new TextBlock
            {
                Text = details + " System boots and operates normally. Boot files reside on a secondary drive. Ensure both drives stay connected.",
                FontSize = 10.5,
                Foreground = _textSecondary,
                TextWrapping = TextWrapping.Wrap
            });
            b.Child = sp;
            return b;
        }

        private UIElement CreateRolePill(string label, SolidColorBrush color)
        {
            Border p = new Border
            {
                Background = _bgSubtle,
                BorderBrush = color,
                BorderThickness = new Thickness(1),
                CornerRadius = new CornerRadius(6),
                Padding = new Thickness(5, 1, 5, 1),
                Margin = new Thickness(0, 0, 4, 0),
                VerticalAlignment = VerticalAlignment.Center
            };
            p.Child = new TextBlock
            {
                Text = label,
                FontSize = 9,
                FontWeight = FontWeights.Bold,
                Foreground = color
            };
            return p;
        }

        private UIElement CreateEventRow(string label, string val, SolidColorBrush valColor)
        {
            Grid g = new Grid { Margin = new Thickness(0, 2, 0, 2) };
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(2.2, GridUnitType.Star) });
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(3, GridUnitType.Star) });

            TextBlock l = new TextBlock { Text = label, FontSize = 11, Foreground = _textSecondary };
            TextBlock v = new TextBlock { Text = val, FontSize = 11, FontWeight = FontWeights.SemiBold, Foreground = valColor, TextWrapping = TextWrapping.Wrap };

            g.Children.Add(l);
            Grid.SetColumn(l, 0);
            g.Children.Add(v);
            Grid.SetColumn(v, 1);
            return g;
        }

        private static bool SafeSetClipboardText(string text)
        {
            if (string.IsNullOrEmpty(text)) return false;
            for (int i = 0; i < 10; i++)
            {
                try
                {
                    Clipboard.SetDataObject(text, true);
                    return true;
                }
                catch
                {
                    System.Threading.Thread.Sleep(60);
                }
            }
            return false;
        }

        // One-click copy. Success shows green "Copied!" for 2 s. Failure (clipboard locked by another
        // process after 10 retries) shows red "Copy failed" for 2 s instead of failing silently.
        private void CopyReportToClipboard()
        {
            try
            {
                string payload = _latestReport != null ? _latestReport.ToFormattedPayload() : "";
                if (string.IsNullOrEmpty(payload)) return;
                bool ok = SafeSetClipboardText(payload);
                ShowCopyFeedback(ok);
            }
            catch
            {
                ShowCopyFeedback(false);
            }
        }

        // Repeated clicks restart one shared timer, so the label never resets early from a stale timer.
        private void ShowCopyFeedback(bool success)
        {
            _isCopiedState = true;
            _btnCopyText.Text = success ? "Copied!" : "Copy failed";
            _btnCopyReport.Background = success ? _colorOk : _colorCritical;
            if (_btnCopyIcon != null)
            {
                _btnCopyIcon.Data = Geometry.Parse(success ? "M5 13l4 4L19 7" : "M6 6l12 12M18 6L6 18");
            }

            if (_copyResetTimer == null)
            {
                _copyResetTimer = new DispatcherTimer(DispatcherPriority.Normal, Dispatcher);
                _copyResetTimer.Interval = TimeSpan.FromSeconds(2);
                _copyResetTimer.Tick += (s, e) =>
                {
                    _copyResetTimer.Stop();
                    _isCopiedState = false;
                    _btnCopyText.Text = "Copy Report";
                    _btnCopyReport.Background = _btnCopyReport.IsMouseOver ? _accentBtnHover : _accentBtn;
                    if (_btnCopyIcon != null)
                    {
                        _btnCopyIcon.Data = Geometry.Parse("M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2v3m2 4H10m0 0l3-3m-3 3l3 3");
                    }
                };
            }
            _copyResetTimer.Stop();
            _copyResetTimer.Start();
        }

        private void OpenWebAi()
        {
            CopyReportToClipboard();
            try
            {
                Process.Start(new ProcessStartInfo
                {
                    FileName = _latestReport != null ? _latestReport.BuildWebHandoffUrl() : "https://pcfixtech.my.id/troubleshoot",
                    UseShellExecute = true
                });
            }
            catch { }
        }
    }
}
