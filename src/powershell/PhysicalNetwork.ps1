# SPDX-License-Identifier: GPL-3.0-or-later
# Loaded only after physical recovery is explicitly configured. Native observations
# avoid spawning commands or interpreting localized adapter-status strings.
if (-not ('ProgramSplit.PhysicalNetwork' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace ProgramSplit {
 public sealed class PhysicalSnapshot {
  public Guid Guid; public uint Index,Type; public string Name,Description;
  public bool Hardware,Paused,LowPower,AdminUp,LinkUp;
  public ulong SentBytes,ReceivedBytes;
 }
 public sealed class WirelessSnapshot {
  public int State=-1; public bool RadioOn,Visible; public string Profile;
  public uint Signal;
 }
 public static class PhysicalNetwork {
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Row {
   public ulong Luid; public uint Index; public Guid Guid;
   [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string Alias;
   [MarshalAs(UnmanagedType.ByValTStr,SizeConst=257)] public string Description;
   public uint AddressLength;
   [MarshalAs(UnmanagedType.ByValArray,SizeConst=32)] public byte[] Address;
   [MarshalAs(UnmanagedType.ByValArray,SizeConst=32)] public byte[] PermanentAddress;
   public uint Mtu,Type,TunnelType,MediaType,PhysicalMediumType,AccessType,DirectionType;
   public byte Flags; public uint OperStatus,AdminStatus,MediaConnectState;
   public Guid NetworkGuid; public uint ConnectionType;
   public ulong TxSpeed,RxSpeed,InOctets,InUcastPkts,InNUcastPkts,InDiscards,InErrors,InUnknownProtos,
    InUcastOctets,InMulticastOctets,InBroadcastOctets,OutOctets,OutUcastPkts,OutNUcastPkts,
    OutDiscards,OutErrors,OutUcastOctets,OutMulticastOctets,OutBroadcastOctets,OutQLen;
  }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct WifiInterface {
   public Guid Guid; [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string Description;
   public int State;
  }
  [StructLayout(LayoutKind.Sequential)] struct Ssid {
   public uint Length; [MarshalAs(UnmanagedType.ByValArray,SizeConst=32)] public byte[] Bytes;
  }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Network {
   [MarshalAs(UnmanagedType.ByValTStr,SizeConst=256)] public string Profile;
   public Ssid Ssid; public int BssType; public uint Bssids;
   [MarshalAs(UnmanagedType.Bool)] public bool Connectable;
   public uint Reason,PhyCount;
   [MarshalAs(UnmanagedType.ByValArray,SizeConst=8)] public int[] PhyTypes;
   [MarshalAs(UnmanagedType.Bool)] public bool MorePhy;
   public uint Signal; [MarshalAs(UnmanagedType.Bool)] public bool Security;
   public uint Auth,Cipher,Flags,Reserved;
  }
  [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Connection {
   public uint Mode; [MarshalAs(UnmanagedType.LPWStr)] public string Profile;
   public IntPtr Ssid,Bssids; public uint BssType,Flags;
  }
  [DllImport("iphlpapi.dll")] static extern uint ConvertInterfaceGuidToLuid(ref Guid guid,out ulong luid);
  [DllImport("iphlpapi.dll")] static extern uint GetIfEntry2(ref Row row);
  [DllImport("wlanapi.dll")] static extern uint WlanOpenHandle(uint version,IntPtr reserved,out uint negotiated,out IntPtr client);
  [DllImport("wlanapi.dll")] static extern uint WlanCloseHandle(IntPtr client,IntPtr reserved);
  [DllImport("wlanapi.dll")] static extern void WlanFreeMemory(IntPtr memory);
  [DllImport("wlanapi.dll")] static extern uint WlanEnumInterfaces(IntPtr client,IntPtr reserved,out IntPtr list);
  [DllImport("wlanapi.dll")] static extern uint WlanQueryInterface(IntPtr client,ref Guid guid,uint opcode,IntPtr reserved,out uint size,out IntPtr data,out uint kind);
  [DllImport("wlanapi.dll")] static extern uint WlanGetAvailableNetworkList(IntPtr client,ref Guid guid,uint flags,IntPtr reserved,out IntPtr list);
  [DllImport("wlanapi.dll")] static extern uint WlanGetProfileList(IntPtr client,ref Guid guid,IntPtr reserved,out IntPtr list);
  [DllImport("kernel32.dll")] public static extern ulong GetTickCount64();
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
  [return:MarshalAs(UnmanagedType.Bool)] static extern bool MoveFileEx(string source,string destination,uint flags);
  [DllImport("wlanapi.dll")] static extern uint WlanScan(IntPtr client,ref Guid guid,IntPtr ssid,IntPtr ie,IntPtr reserved);
  [DllImport("wlanapi.dll",CharSet=CharSet.Unicode)] static extern uint WlanConnect(IntPtr client,ref Guid guid,ref Connection connection,IntPtr reserved);
  static void Check(uint error) { if(error!=0)throw new Win32Exception((int)error); }
  static IntPtr Open() { uint version;IntPtr client;Check(WlanOpenHandle(2,IntPtr.Zero,out version,out client));return client; }
  public static PhysicalSnapshot Read(Guid guid) {
   var row=new Row();Check(ConvertInterfaceGuidToLuid(ref guid,out row.Luid));Check(GetIfEntry2(ref row));
   return new PhysicalSnapshot {Guid=row.Guid,Index=row.Index,Type=row.Type,Name=row.Alias,Description=row.Description,
    Hardware=(row.Flags&1)!=0 && (row.Flags&2)==0 && row.TunnelType==0,Paused=(row.Flags&32)!=0,
    LowPower=(row.Flags&64)!=0,AdminUp=row.AdminStatus==1,LinkUp=row.MediaConnectState==1,
    SentBytes=row.OutOctets,ReceivedBytes=row.InOctets};
  }
  public static WirelessSnapshot ReadWireless(Guid guid,string profile) {
   IntPtr client=Open(),memory=IntPtr.Zero;var result=new WirelessSnapshot {Profile=profile};
   try {
    Check(WlanEnumInterfaces(client,IntPtr.Zero,out memory));int count=Marshal.ReadInt32(memory);
    if(count<0||count>256)throw new InvalidOperationException("Invalid WLAN interface count.");
    int size=Marshal.SizeOf(typeof(WifiInterface));
    for(int i=0;i<count;i++) {
     var item=(WifiInterface)Marshal.PtrToStructure(IntPtr.Add(memory,8+i*size),typeof(WifiInterface));
     if(item.Guid==guid){result.State=item.State;break;}
    }
    WlanFreeMemory(memory);memory=IntPtr.Zero;
    // WLAN_INTF_OPCODE_RADIO_STATE=4; every PHY must have both radios on.
    uint bytes,kind;Check(WlanQueryInterface(client,ref guid,4,IntPtr.Zero,out bytes,out memory,out kind));
    int phys=Marshal.ReadInt32(memory);result.RadioOn=phys>0&&phys<=64&&bytes>=4+12*phys;
    if(result.RadioOn)for(int i=0;i<phys;i++) {
     if(Marshal.ReadInt32(memory,4+12*i+4)!=1||Marshal.ReadInt32(memory,4+12*i+8)!=1)result.RadioOn=false;
    }
    WlanFreeMemory(memory);memory=IntPtr.Zero;
    if(result.State!=4||!result.RadioOn)return result;
    Check(WlanGetAvailableNetworkList(client,ref guid,0,IntPtr.Zero,out memory));count=Marshal.ReadInt32(memory);
    if(count<0||count>4096)throw new InvalidOperationException("Invalid WLAN network count.");
    size=Marshal.SizeOf(typeof(Network));
    for(int i=0;i<count;i++) {
     var network=(Network)Marshal.PtrToStructure(IntPtr.Add(memory,8+i*size),typeof(Network));
     if(String.Equals(network.Profile,profile,StringComparison.Ordinal)&&network.Connectable&&network.Bssids>0) {
      result.Visible=true;result.Signal=network.Signal;break;
     }
    }
    return result;
   } finally {if(memory!=IntPtr.Zero)WlanFreeMemory(memory);WlanCloseHandle(client,IntPtr.Zero);}
  }
  public static void Scan(Guid guid) {
   IntPtr client=Open();try{Check(WlanScan(client,ref guid,IntPtr.Zero,IntPtr.Zero,IntPtr.Zero));}
   finally{WlanCloseHandle(client,IntPtr.Zero);}
  }
  public static bool HasAllUserProfile(Guid guid,string profile) {
   IntPtr client=Open(),memory=IntPtr.Zero;
   try {
    Check(WlanGetProfileList(client,ref guid,IntPtr.Zero,out memory));int count=Marshal.ReadInt32(memory);
    if(count<0||count>4096)throw new InvalidOperationException("Invalid WLAN profile count.");
    // WLAN_PROFILE_INFO: WCHAR name[256], DWORD flags. Bit 2 means per-user.
    for(int i=0;i<count;i++) {
     IntPtr item=IntPtr.Add(memory,8+i*516);
     if(String.Equals(Marshal.PtrToStringUni(item),profile,StringComparison.Ordinal)&&
        (Marshal.ReadInt32(item,512)&2)==0)return true;
    }
    return false;
   } finally{if(memory!=IntPtr.Zero)WlanFreeMemory(memory);WlanCloseHandle(client,IntPtr.Zero);}
  }
  public static void AtomicMove(string source,string destination) {
   if(!MoveFileEx(source,destination,1|8))throw new Win32Exception(Marshal.GetLastWin32Error());
  }
  public static void Connect(Guid guid,string profile) {
   IntPtr client=Open();try{
    var connection=new Connection {Mode=0,Profile=profile,BssType=1};
    Check(WlanConnect(client,ref guid,ref connection,IntPtr.Zero));
   } finally{WlanCloseHandle(client,IntPtr.Zero);}
  }
 }
}
'@
}
