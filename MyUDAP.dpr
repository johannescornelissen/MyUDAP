program MyUDAP;

// based on code of Robin Bowes <robin@robinbowes.com>
// https://github.com/robinbowes/net-udap

// because this is based on Robin Bowes code this also is published under the same license

{
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
}

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Winsock2,
  System.Classes,
  System.Types,
  System.Generics.Collections,
  System.Generics.Defaults,
  System.SysUtils;

const
  PORT_UDAP                     = $4578; // 17784;

  MAC_ZERO                      : array[0..5] of byte = (0,0,0,0,0,0);

  UCP_METHOD_ZERO               = 0;
  UCP_METHOD_DISCOVER           = 1;
  UCP_METHOD_GET_IP             = 2;
  UCP_METHOD_SET_IP             = 3;
  UCP_METHOD_RESET              = 4;
  UCP_METHOD_GET_DATA           = 5;
  UCP_METHOD_SET_DATA           = 6;
  UCP_METHOD_ERROR              = 7;
  UCP_METHOD_CREDENTIALS_ERROR  = 8;
  UCP_METHOD_ADV_DISCOVER       = 9;
  UCP_METHOD_TEN                = 10;
  UCP_METHOD_GET_UUID           = 11;

  UCP_CODE_ZERO                 = $00;
  UCP_CODE_ONE                  = $01;
  UCP_CODE_DEVICE_NAME          = $02;
  UCP_CODE_DEVICE_TYPE          = $03;
  UCP_CODE_USE_DHCP             = $04;
  UCP_CODE_IP_ADDR              = $05;
  UCP_CODE_SUBNET_MASK          = $06;
  UCP_CODE_GATEWAY_ADDR         = $07;
  UCP_CODE_EIGHT                = $08;
  UCP_CODE_FIRMWARE_REV         = $09;
  UCP_CODE_HARDWARE_REV         = $0a;
  UCP_CODE_DEVICE_ID            = $0b;
  UCP_CODE_DEVICE_STATUS        = $0c;
  UCP_CODE_UUID                 = $0d;

  IP_ZERO                       : array[0..3] of byte = (0,0,0,0);
  PORT_ZERO                     : array[0..1] of byte = (0,0);

  // Address Types
  ADDR_TYPE_RAW                 = 0;
  ADDR_TYPE_ETH                 = 1;
  ADDR_TYPE_UDP                 = 2;
  ADDR_TYPE_THREE               = 3;

  // Boradcast
  BROADCAST_OFF                 = 0;
  BROADCAST_ON                  = 1;

  // DHCP
  DHCP_OFF                      = 0;
  DHCP_ON                       = 1;

  // Misc constants
  UAP_CLASS_UCP                 : array[0..3] of byte = (0,1,0,1);
  UDAP_TIMEOUT                  = 1;
  UDAP_TYPE_UCP                 = $C001;

  UDP_MAX_MSG_LEN               = 1500;

  ListenerSocketTimeOut         = 1000; // 1 second

type
  TDataParameter = record
    name: string;
    help: string;
    offset:Integer;
    length: Integer;
    pack: Integer; // 0: byte 1: network byte order inet address, 2: binary a64, 3: 0-term ascii padded 4: network order hex string
  end;

const
  DataParameters: array[0..25] of TDataParameter =
  (
    ( name: 'lan_ip_mode'; help:'0 - Use static IP details, 1 - use DHCP to discover IP details';
      offset:4; length:1; pack:0),
    ( name: 'lan_network_address'; help:'IP address of device, (e.g. 192.168.1.10)';
      offset:5; length:4; pack:1),
    ( name: 'lan_subnet_mask'; help:'Subnet mask of local network, (e.g. 255.255.255.0)';
      offset:9; length:4; pack:1),
    ( name: 'lan_gateway'; help:'IP address of default network gateway, (e.g. 192.168.1.1)';
      offset:13; length:4; pack:1),
    ( name: 'hostname'; help:'Device hostname (is this set automatically?)';
      offset:17; length:33; pack:3),
    ( name: 'bridging'; help:'Use device as a wireless bridge (not sure about this)';
      offset:50; length:1; pack:0),
    ( name: 'interface'; help:'0 - wireless, 1 - wired (is set to 128 after factory reset)';
      offset:52; length:1; pack:0),
    ( name: 'primary_dns'; help:'IP address of primary DNS server';
      offset:59; length:4; pack:1),
    ( name: 'secondary_dns'; help:'IP address of secondary DNS server';
      offset:67; length:4; pack:1),
    ( name: 'server_address'; help:'IP address of currently active server (either Squeezenetwork or local server';
      offset:71; length:4; pack:1),
    ( name: 'squeezecenter_address'; help:'IP address of local Squeezecenter server';
      offset:79; length:4; pack:1),
    ( name: 'squeezecenter_name'; help:'Name of local Squeezecenter server (???)';
      offset:83; length:33; pack:3),
    ( name: 'wireless_mode'; help:'0 - Infrastructure, 1 - Ad Hoc';
      offset:173; length:1; pack:0),
    ( name: 'wireless_SSID'; help:'Wireless network name';
      offset:183; length:33; pack:3),
    ( name: 'wireless_channel'; help:'Wireless channel (used by AdHoc mode???)';
      offset:216; length:1; pack:0),
    ( name: 'wireless_region_id'; help:'4 - US, 6 - CA, 7 - AU, 13 - FR, 14 - EU, 16 - JP, 21 - TW, 23 - CH';
      offset:218; length:1; pack:0),
    ( name: 'wireless_keylen'; help:'Length of wireless key, (0 - 64-bit, 1 - 128-bit)';
      offset:220; length:1; pack:0),
    ( name: 'wireless_wep_key_0'; help:'WEP Key 0 - enter in hex';
      offset:222; length:13; pack:4),
    ( name: 'wireless_wep_key_1'; help:'WEP Key 1 - enter in hex';
      offset:235; length:13; pack:4),
    ( name: 'wireless_wep_key_2'; help:'WEP Key 2 - entr in hex';
      offset:248; length:13; pack:4),
    ( name: 'wireless_wep_key_3'; help:'WEP Key 3 - enter in hex';
      offset:261; length:13; pack:4),
    ( name: 'wireless_wep_on'; help:'0 - WEP Off, 1 - WEP On';
      offset:274; length:1; pack:0),
    ( name: 'wireless_wpa_cipher'; help:'1 - TKIP, 2 - AES, 3 - TKIP & AES';
      offset:275; length:1; pack:0),
    ( name: 'wireless_wpa_mode'; help:'1 - WPA, 2 - WPA2';
      offset:276; length:1; pack:0),
    ( name: 'wireless_wpa_on'; help:'0 - WPA Off, 1 - WPA On';
      offset:277; length:1; pack:0),
    ( name: 'wireless_wpa_psk'; help:'WPA Public Shared Key';
      offset:278; length:64; pack:2)
  );

type
  TCustomStringComparer = class(TCustomComparer<String>)
  public
    function Compare(const Left, Right: String): Integer; override;
    function Equals(const Left, Right: String): Boolean; override;
    function GetHashCode(const Value: String): Integer; override;
  end;

  TUDAPAddress = packed record
  private
    function get_address_ip_port: UInt16;
    procedure set_address_ip_port(aValue: UInt16);
  public
    procedure Clear(aAddressType: byte);
    procedure setMAC(const aMAC: array of byte);
    procedure setIPAddress(const aIP: array of byte);
    property address_ip_port: UInt16 read get_address_ip_port write set_address_ip_port;

    function toString: string;

    // data
    case address_type: byte of
      ADDR_TYPE_ETH: (address_mac: array[0..5] of byte);
      ADDR_TYPE_UDP: (address_ip: array[0..3] of byte; address_ip_portN: UInt16);
      ADDR_TYPE_RAW: (address_raw: array[0..5] of byte);
      ADDR_TYPE_THREE: (address_three: array[0..5] of byte)
  end;

  TUDAPMessage = packed record
  class function Create: TUDAPMessage; overload; static;
  class function Create(const aBuffer: array of byte): TUDAPMessage; overload; static;
  private
    function get_seq: UInt16;
    function get_ucp_method: UInt16;
    function get_udap_type: Uint16;
    procedure set_seq(const aValue: UInt16);
    procedure set_ucp_method(const aValue: UInt16);
    procedure set_udap_type(const aValue: Uint16);
    function ucp_method_name: string;
  public
    // standard header
    dst_broadcast: byte; // 1
    dst_address: TUDAPAddress; // 7
    src_broadcast: byte; // 1
    src_address: TUDAPAddress; // 7
    seqN: UInt16; // 2
    udap_typeN: Uint16; // 2
    ucp_flags: byte; // 1
    ucp_class: array[0..3] of byte; // 4
    ucp_methodN: UInt16; // 2

    extra_data: TArray<byte>;

    property seq: UInt16 read get_seq write set_seq;
    property udap_type: Uint16 read get_udap_type write set_udap_type;
    property ucp_method: UInt16 read get_ucp_method write set_ucp_method;

    // build message types
    function Discover: TUDAPMessage;
    function GetIP(const aMAC: array of byte): TUDAPMessage;
    function SetIP(const aMAC, aIPAddress, aNetmask, aGateway, aDHCPOnOff: array of byte): TUDAPMessage;
    function Reset(const aMAC: array of byte): TUDAPMessage;
    function GetData(const aMAC: array of byte): TUDAPMessage;
    function SetData(const aMAC, aData: array of byte): TUDAPMessage;

    // build resulting buffer to send
    function buffer: TArray<byte>;

    procedure debug;
  end;

  TUDAPDeviceParameter = record
    name: string;
    value: string;
    pack: Integer;
  end;

  TUDAPDevice = class
  constructor Create(const aResponse: TUDAPMessage);
  destructor Destroy; override;
  private
    fParameters: TDictionary<string, string>;
  public
    property parameters: TDictionary<string, string> read fParameters;
    procedure Update(const aResponse: TUDAPMessage);
  end;

  TUDAPControl = class
  constructor Create;
  Destructor Destroy; override;
  private
    fSocket: TSocket;
    fListenerThread: TThread;
    fdevices: TDictionary<TUDAPAddress, TUDAPDevice>;
    function sendCommand(aPort: Integer; const aBuffer: TArray<byte>): Boolean;
    procedure handleReceivedData;
    function ParameterValue(aDevice: TUDAPDevice; const aParameterName: string): string;
    procedure ShowParameter(aDevice: TUDAPDevice; const aParameterName: string);
  public
    procedure SendDiscover;
    procedure ShowDetails;
    procedure ListDevices;
  end;

procedure MyCloseSocket(var aSocket: TSocket);
begin
  if aSocket<>INVALID_SOCKET then
  begin
    try
      shutdown(aSocket, SD_BOTH);
    finally
      closesocket(aSocket);
    end;
    aSocket := INVALID_SOCKET;
  end;
end;

function join(s: TArray<TArray<byte>>): TArray<byte>;
var
  i: Integer;
  c: Integer;
begin
  c := 0;
  for i := 0 to length(s)-1
  do c := c+length(s[i]);
  setLength(Result, c);
  c := 0;
  for i := 0 to length(s)-1 do
  begin
    move(s[i][0], result[c], length(s[i]));
    c := c+length(s[i]);
  end;
end;

function bytesToHex(const aBytes: TArray<byte>): string; overload;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(aBytes)-1
  do Result := Result+aBytes[i].ToHexString(2);
end;

function bytesToString(const aBytes: TArray<byte>): string; overload;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(aBytes)-1 do
  begin
    if aBytes[i]<>0
    then Result := Result+Chr(aBytes[i]);
  end;
end;

function bytesToHexNetworkOrder(const aBytes: TArray<byte>): string;
var
  i: Integer;
begin
  Result := '';
  for i := Length(aBytes)-1 downto 0
  do Result := Result+aBytes[i].ToHexString(2);
end;

function bytesToHex(const aBytes: array of byte): string; overload;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(aBytes)-1
  do Result := Result+aBytes[i].ToHexString(2);
end;

function bytesToTArray(const aBytes: array of Byte): TArray<byte>;
begin
  setLength(Result, Length(aBytes));
  if Length(aBytes)>0
  then move(aBytes[0], Result[0], Length(aBytes));
end;

function UInt16ToTArray(i: UInt16): TArray<byte>;
begin
  // network order ie reverse to intel
  setLength(Result, 2);
  Result[0] := i shr 8;
  Result[1] := i and $FF;
end;

function bytesToUInt16(aByte0, aByte1: Byte): UInt16;
begin
  Result := aByte1 or (aByte0 shl 8);
end;

function bytesToIPAddress(const aBytes: array of byte): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to length(aBytes)-2
  do Result := Result+aBytes[i].ToString+'.';
  Result := Result+aBytes[length(aBytes)-1].ToString;
end;

function FindDataParameterOnOffset(aOffset: Integer): Integer;
begin
  Result := Length(DataParameters)-1;
  while (Result>=0) and (DataParameters[Result].offset<>aOffset)
  do Result := Result-1;
end;

{ TCustomStringComparer }

function TCustomStringComparer.Compare(const Left, Right: String): Integer;
begin
  { Make a case-insensitive comparison. }
  Result := CompareText(Left, Right);
end;

function TCustomStringComparer.Equals(const Left, Right: String): Boolean;
begin
  { Make a case-insensitive comparison. }
  Result := CompareText(Left, Right) = 0;
end;

function TCustomStringComparer.GetHashCode(const Value: String): Integer;
begin
  { Generate a hash code. Simply return the length of the string as its hash code. }
  Result := Length(Value);
end;


{ TUDAAddress }

procedure TUDAPAddress.Clear;
begin
  FillChar(Self, SizeOf(Self), 0);
  address_type := aAddressType;
end;

function TUDAPAddress.get_address_ip_port: UInt16;
begin
  Result := ntohs(address_ip_portN);
end;

procedure TUDAPAddress.setIPAddress(const aIP: array of byte);
begin
  move(aIP[0], address_ip[0], Length(address_ip));
end;

procedure TUDAPAddress.setMAC(const aMAC: array of byte);
begin
  move(aMAC[0], address_mac[0], Length(address_mac));
end;

procedure TUDAPAddress.set_address_ip_port(aValue: UInt16);
begin
  address_ip_portN := htons(aValue);
end;

function TUDAPAddress.toString: string;
begin
  case address_type of
    ADDR_TYPE_ETH:
      Result :=
        address_mac[0].ToHexString(2)+':'+address_mac[1].ToHexString(2)+':'+
        address_mac[2].ToHexString(2)+':'+address_mac[3].ToHexString(2)+':'+
        address_mac[4].ToHexString(2)+':'+address_mac[5].ToHexString(2);
    ADDR_TYPE_UDP:
      Result :=
        address_ip[0].ToString+'.'+address_ip[1].ToString+'.'+
        address_ip[2].ToString+'.'+address_ip[3].ToString+':'+address_ip_port.ToString;
    ADDR_TYPE_RAW:
      Result := bytesToHex(address_raw);
    ADDR_TYPE_THREE:
      Result := bytesToHex(address_three);
  else
    Result := bytesToHex(address_raw);
  end;
end;

{ TUDAPMessage }

function TUDAPMessage.buffer: TArray<byte>;
begin
  setLength(Result, 27+Length(extra_data));
  move(Self, Result[0], 27);
  if length(extra_data)>0
  then move(extra_data[0], Result[27], length(extra_data));
end;

class function TUDAPMessage.Create: TUDAPMessage;
begin
  Result.dst_broadcast := BROADCAST_ON;
  Result.dst_address.Clear(ADDR_TYPE_ETH);
  Result.src_broadcast := BROADCAST_OFF;
  Result.src_address.Clear(ADDR_TYPE_UDP);
  Result.seq := 1;
  Result.udap_type := UDAP_TYPE_UCP;
  Result.ucp_flags := 1;
  move(UAP_CLASS_UCP[0], Result.ucp_class[0], SizeOf(UAP_CLASS_UCP));
  Result.ucp_method := UCP_METHOD_ZERO;
  setLength(Result.extra_data, 0);
end;

class function TUDAPMessage.Create(const aBuffer: array of byte): TUDAPMessage;
begin
  move(aBuffer[0], Result, 27);
  if length(aBuffer)>27 then
  begin
    setLength(Result.extra_data, length(aBuffer)-27);
    move(aBuffer[27], Result.extra_data[0], length(aBuffer)-27);
  end
  else setLength(Result.extra_data, 0);
end;

procedure TUDAPMessage.debug;
var
  num_items: Word;
  i: Integer;
  upc_code: byte;
  data_length: byte;
  data: TArray<byte>;
  offset: UInt16;
  len: UInt16;
  p: Integer;
begin
  WriteLn('dst_broadcast: ', dst_broadcast);
  WriteLn('dst_address: ', dst_address.toString);
  WriteLn('src_broadcast: ', src_broadcast);
  WriteLn('src_address: ', src_address.toString);
  WriteLn('seq: ', seq);
  WriteLn('udap_type: ', udap_type.ToHexString(4));
  WriteLn('ucp_flags ', ucp_flags);
  WriteLn('uap_class: ', bytesToHex(ucp_class));
  WriteLn('ucp_method: ', ucp_method_name);
  case ucp_method of
    UCP_METHOD_DISCOVER,
    UCP_METHOD_ADV_DISCOVER,
    UCP_METHOD_GET_IP:
      begin
        i := 0;
        while i<length(extra_data) do
        begin
          upc_code := extra_data[i];
          i := i+1;
          data_length := extra_data[i];
          i := i+1;
          setLength(data, data_length);
          if data_length>0
          then move(extra_data[i], data[0], data_length);
          i := i+data_length;
          case upc_code of
            UCP_CODE_ZERO:            WriteLn('extra data upc_code: ZERO: '+bytesTohex(data));
            UCP_CODE_ONE:             WriteLn('extra data upc_code: ONE: '+bytesTohex(data));
            UCP_CODE_DEVICE_NAME:     WriteLn('extra data upc_code: DEVICE_NAME: '+bytesToString(data));
            UCP_CODE_DEVICE_TYPE:     WriteLn('extra data upc_code: DEVICE_TYPE: '+bytesToString(data));
            UCP_CODE_USE_DHCP:        WriteLn('extra data upc_code: USE_DHCP: '+bytesTohex(data));
            UCP_CODE_IP_ADDR:         WriteLn('extra data upc_code: IP_ADDR: '+bytesToIPAddress(data));
            UCP_CODE_SUBNET_MASK:     WriteLn('extra data upc_code: SUBNET_MASK: '+bytesToIPAddress(data));
            UCP_CODE_GATEWAY_ADDR:    WriteLn('extra data upc_code: GATEWAY_ADDR: '+bytesToIPAddress(data));
            UCP_CODE_EIGHT:           WriteLn('extra data upc_code: EIGHT: '+bytesTohex(data));
            UCP_CODE_FIRMWARE_REV:    WriteLn('extra data upc_code: FIRMWARE_REV: '+bytesToString(data));
            UCP_CODE_HARDWARE_REV:    WriteLn('extra data upc_code: HARDWARE_REV: '+bytesToString(data));
            UCP_CODE_DEVICE_ID:       WriteLn('extra data upc_code: DEVICE_ID: '+bytesToString(data));
            UCP_CODE_DEVICE_STATUS:   WriteLn('extra data upc_code: DEVICE_STATUS: '+bytesToString(data));
            UCP_CODE_UUID:            WriteLn('extra data upc_code: UUID: '+bytesToHex(data));
          else
            WriteLn('>> extra data unknown upc_code: '+upc_code.tostring+': '+bytesTohex(data));
          end;
        end;
      end;
    UCP_METHOD_GET_DATA:
      begin
        num_items := bytesToUInt16(extra_data[0],extra_data[1]);
        WriteLn('extra data parameters '+num_items.ToString);
        i := 2;
        while i<length(extra_data) do
        begin
          offset := bytesToUInt16(extra_data[i],extra_data[i+1]);
          i := i+2;
          len := bytesToUInt16(extra_data[i],extra_data[i+1]);
          i := i+2;
          setLength(data, len);
          if len>0 then
          begin
            move(extra_data[i], data[0], len);
            i := i+len;
          end;
          p := FindDataParameterOnOffset(offset);
          if p>=0 then
          begin
            case DataParameters[p].pack of
              // 0: byte 1: network byte order inet address, 2: binary a64, 3: 0-term ascii padded 4: network order hex string
              0: WriteLn('extra data parameter '+DataParameters[p].name+': '+data[0].toString);
              1: WriteLn('extra data parameter '+DataParameters[p].name+': '+bytesToIPAddress(data));
              2: WriteLn('extra data parameter '+DataParameters[p].name+': '+bytesToHex(data));
              3: WriteLn('extra data parameter '+DataParameters[p].name+': '+bytesToString(data));
              4: WriteLn('extra data parameter '+DataParameters[p].name+': '+bytesToHexNetworkOrder(data));
            else
              WriteLn('>> extra data parameter (unkown type) '+DataParameters[p].name+': '+bytesToHex(data));
            end;
          end
          else WriteLn('## extra data unknown parameter ('+offset.ToString+'): '+bytesToHex(data));
        end;
      end;
    UCP_METHOD_SET_IP:
      begin
        WriteLn('SET_IP data (?): ', bytesToHex(extra_data));
      end;
  else
    WriteLn('extra data: ', bytesToHex(extra_data));
  end;
end;

function TUDAPMessage.Discover: TUDAPMessage;
begin
  Result := Self;
  Result.ucp_method := UCP_METHOD_ADV_DISCOVER;
end;

function TUDAPMessage.GetData(const aMAC: array of byte): TUDAPMessage;
var
  credentials: TArray<byte>;
  parameters: TArray<byte>;
  pc: UInt16;
  i: Integer;
  pcN: UInt16;
  offsetN: UInt16;
  lengthN: UInt16;
begin
  Result := Self;
  Result.ucp_method := UCP_METHOD_GET_DATA;
  Result.dst_address.Clear(ADDR_TYPE_ETH);
  Result.dst_address.setMAC(aMAC);

  setLength(credentials, 32);
  fillChar(credentials[0], 32, 0);
  pc := length(DataParameters);
  pcN := htons(pc);
  setLength(parameters, sizeof(uint16)+pc*sizeof(uint16)*2);

  move(pcN, parameters[0], sizeof(pc));
  for i := 0 to pc-1 do
  begin
    offsetN := htons(DataParameters[i].offset);
    lengthN := htons(DataParameters[i].length);
    move(offsetN, parameters[sizeof(pcN)+i*(sizeof(offsetN)+sizeof(lengthN))], sizeof(offsetN));
    move(lengthN, parameters[sizeof(pcN)+i*(sizeof(offsetN)+sizeof(lengthN))+sizeof(offsetN)], sizeof(lengthN));
  end;
  Result.extra_data := join([credentials,parameters]);
end;

function TUDAPMessage.GetIP(const aMAC: array of byte): TUDAPMessage;
begin
  Result := Self;
  Result.ucp_method := UCP_METHOD_GET_IP;
  Result.dst_address.Clear(ADDR_TYPE_ETH);
  Result.dst_address.setMAC(aMAC);
  // 010100042016EA8600020000000000000001C00101000100010002
end;

function TUDAPMessage.get_seq: UInt16;
begin
  Result := ntohs(seqN);
end;

function TUDAPMessage.get_ucp_method: UInt16;
begin
  Result := ntohs(ucp_methodN);
end;

function TUDAPMessage.get_udap_type: Uint16;
begin
  Result := ntohs(udap_typeN);
end;

function TUDAPMessage.Reset(const aMAC: array of byte): TUDAPMessage;
begin
  Result := Self;
  Result.ucp_method := UCP_METHOD_RESET;
  Result.dst_address.Clear(ADDR_TYPE_ETH);
  Result.dst_address.setMAC(aMAC);
end;

function TUDAPMessage.SetData(const aMAC, aData: array of byte): TUDAPMessage;
begin
  Result := Self;
  Result.ucp_method := UCP_METHOD_GET_DATA;
  Result.dst_address.Clear(ADDR_TYPE_ETH);
  Result.dst_address.setMAC(aMAC);
  Result.extra_data := bytesToTArray(aData);
end;

function TUDAPMessage.SetIP(const aMAC, aIPAddress, aNetmask, aGateway,
  aDHCPOnOff: array of byte): TUDAPMessage;
begin
  // todo:
  Result := Self;
  Result.ucp_method := UCP_METHOD_SET_IP;
  Result.dst_address.Clear(ADDR_TYPE_ETH);
  Result.dst_address.setMAC(aMAC);
  Result.extra_data := join([
    bytesToTArray(aIPAddress),
    bytesToTArray(aNetmask),
    bytesToTArray(aGateway),
    bytesToTArray(aDHCPOnOff)]);
end;

procedure TUDAPMessage.set_seq(const aValue: UInt16);
begin
  seqN := htons(aValue);
end;

procedure TUDAPMessage.set_ucp_method(const aValue: UInt16);
begin
  ucp_methodN := htons(aValue);
end;

procedure TUDAPMessage.set_udap_type(const aValue: Uint16);
begin
  udap_typeN := htons(aValue);
end;

function TUDAPMessage.ucp_method_name: string;
begin
  case ucp_method of
    UCP_METHOD_ZERO:                   Result := 'ZERO';
    UCP_METHOD_DISCOVER:               Result := 'DISCOVER';
    UCP_METHOD_GET_IP:                 Result := 'GET_IP';
    UCP_METHOD_SET_IP:                 Result := 'SET_IP';
    UCP_METHOD_RESET:                  Result := 'RESET';
    UCP_METHOD_GET_DATA:               Result := 'GET_DATA';
    UCP_METHOD_SET_DATA:               Result := 'SET_DATA';
    UCP_METHOD_ERROR:                  Result := 'ERROR';
    UCP_METHOD_CREDENTIALS_ERROR:      Result := 'CREDENTIALS_ERROR';
    UCP_METHOD_ADV_DISCOVER:           Result := 'ADV_DISCOVER';
    UCP_METHOD_TEN:                    Result := 'TEN';
    UCP_METHOD_GET_UUID:               Result := 'GET_UUID';
  else
    Result :=                          ucp_method.ToString;
  end;
end;

{ TUDAPDevice }

Constructor TUDAPDevice.Create(const aResponse: TUDAPMessage);
begin
  inherited Create;
  fParameters := TDictionary<string, string>.Create;
  Update(aResponse);
end;

destructor TUDAPDevice.Destroy;
begin
  FreeAndNil(fParameters);
  inherited;
end;

procedure TUDAPDevice.Update(const aResponse: TUDAPMessage);
var
  i: Integer;
  upc_code: byte;
  data_length: byte;
//  num_items: UInt16;
  offset: UInt16;
  len: UInt16;
  p: Integer;
  data: TArray<byte>;
begin
  // parse response and fill in fields
  case aResponse.ucp_method of
    UCP_METHOD_DISCOVER,
    UCP_METHOD_ADV_DISCOVER,
    UCP_METHOD_GET_IP:
      begin
        i := 0;
        while i<length(aResponse.extra_data) do
        begin
          upc_code := aResponse.extra_data[i];
          i := i+1;
          data_length := aResponse.extra_data[i];
          i := i+1;
          setLength(data, data_length);
          if data_length>0
          then move(aResponse.extra_data[i], data[0], data_length);
          i := i+data_length;
          case upc_code of
            UCP_CODE_DEVICE_NAME:     fParameters.AddOrSetValue('DeviceName', bytesToString(data));
            UCP_CODE_DEVICE_TYPE:     fParameters.AddOrSetValue('Devicetype', bytesToString(data));
            UCP_CODE_USE_DHCP:        fParameters.AddOrSetValue('UseDHCP', data[0].toString);
            UCP_CODE_IP_ADDR:         fParameters.AddOrSetValue('IPAddress', bytesToIPAddress(data));
            UCP_CODE_SUBNET_MASK:     fParameters.AddOrSetValue('SubnetMask', bytesToIPAddress(data));
            UCP_CODE_GATEWAY_ADDR:    fParameters.AddOrSetValue('Gateway', bytesToIPAddress(data));
            UCP_CODE_FIRMWARE_REV:    fParameters.AddOrSetValue('FirmwareRevision', bytesToString(data));
            UCP_CODE_HARDWARE_REV:    fParameters.AddOrSetValue('HardwareRevision', bytesToString(data));
            UCP_CODE_DEVICE_ID:       fParameters.AddOrSetValue('DeviceID', bytesToString(data));
            UCP_CODE_DEVICE_STATUS:   fParameters.AddOrSetValue('DeviceStatus', bytesToString(data));
            UCP_CODE_UUID:            fParameters.AddOrSetValue('UUID', TGUID.Create(data).ToString);
          end;
        end;
      end;
    UCP_METHOD_GET_DATA:
      begin
//        num_items := bytesToUInt16(aResponse.extra_data[0], aResponse.extra_data[1]);
        i := 2;
        while i<length(aResponse.extra_data) do
        begin
          offset := bytesToUInt16(aResponse.extra_data[i],aResponse.extra_data[i+1]);
          i := i+2;
          len := bytesToUInt16(aResponse.extra_data[i], aResponse.extra_data[i+1]);
          i := i+2;
          setLength(data, len);
          if len>0 then
          begin
            move(aResponse.extra_data[i], data[0], len);
            i := i+len;
          end;
          p := FindDataParameterOnOffset(offset);
          if p>=0 then
          begin
            case DataParameters[p].pack of
              // 0: byte 1: network byte order inet address, 2: binary a64, 3: 0-term ascii padded 4: network order hex string
              0: fParameters.AddOrSetValue(DataParameters[p].name, data[0].toString);
              1: fParameters.AddOrSetValue(DataParameters[p].name, bytesToIPAddress(data));
              2: fParameters.AddOrSetValue(DataParameters[p].name, bytesToHex(data));
              3: fParameters.AddOrSetValue(DataParameters[p].name, bytesToString(data));
              4: fParameters.AddOrSetValue(DataParameters[p].name, bytesToHexNetworkOrder(data));
            end;
          end;
        end;
      end;
//    UCP_METHOD_SET_IP:
//      begin
//        WriteLn('SET_IP data (?): ', bytesToHex(aResponse.extra_data));
//      end;
//  else
//    WriteLn('extra data: ', bytesToHex(aResponse.extra_data));
  end;
end;

{ TUDAPControl }

constructor TUDAPControl.Create;
var
  localAddress: sockaddr;
  optVal: Integer;
begin
  inherited Create;
  fDevices := TDictionary<TUDAPAddress, TUDAPDevice>.Create;
  fSocket := socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  fillChar(localAddress, SizeOf(localAddress), 0);
  localAddress.sa_family := AF_INET;
  if bind(fSocket, LocalAddress, SizeOf(LocalAddress))=SOCKET_ERROR then
  begin
    MyCloseSocket(fSocket);
    raise Exception.Create('Could not bind to socket: '+IntToStr(WSAGetLastError));
  end;
  optVal := 1; // enable sending broadcast on socket
  if setsockopt(fSocket, SOL_SOCKET, SO_BROADCAST, PAnsiChar(@OptVal), SizeOf(OptVal))=SOCKET_ERROR then
  begin
    MyCloseSocket(fSocket);
    raise Exception.Create('Could not set broadcast option in socket: '+IntToStr(WSAGetLastError));
  end;
  // start listener thread
  fListenerThread := TThread.CreateAnonymousThread(handleReceivedData);
  fListenerThread.NameThreadForDebugging('udp listener');
  fListenerThread.FreeOnTerminate := False;
  fListenerThread.Start;
end;

destructor TUDAPControl.Destroy;
begin
  fListenerThread.Terminate;
  MyCloseSocket(fSocket);
  FreeAndNil(fListenerThread);
  FreeAndNil(fDevices);
  inherited;
end;

procedure TUDAPControl.handleReceivedData;
var
  FDSet: TFDSet;
  TimeVal: TTimeVal;
  remoteAddr: TSockAddr;
  remoteAddrSize: Integer;
  recBuffer: TArray<byte>;
  recbytes: Integer;
  response: TUDAPMessage;
  device: TUDAPDevice;
  key: TUDAPAddress;
begin
  // wait for response
  while not TThread.CheckTerminated do
  begin // there is data
    FDSet.fd_count := 1;
    FDSet.fd_array[0] := fSocket;
    TimeVal.tv_sec := ListenerSocketTimeOut div 1000;
    TimeVal.tv_usec := (ListenerSocketTimeOut*1000) mod 1000000;
    if select(0, @FDSet, nil, nil, @TimeVal)>0 then
    begin
      FillChar(remoteAddr, SizeOf(remoteAddr), 0);
      remoteAddrSize := SizeOf(remoteAddr);
      // get the received data
      setLength(recBuffer, 1024);
      recbytes :=  recvfrom(fSocket, recBuffer[0], Length(recBuffer), 0, remoteAddr, remoteAddrSize);
      if recbytes>=0 then
      begin
        // decode the received data
        setLength(recBuffer, recBytes);
//        WriteLn;
//        WriteLn('received: '+remoteAddr.AddrAndPortStr+': ('+recBytes.ToString+') '+bytesToHex(recBuffer));
        response := TUDAPMessage.Create(recBuffer);
        key := response.src_address;
//        response.debug;
        WriteLn('received '+response.ucp_method_name+' from '+key.toString);
        TMonitor.Enter(fDevices);
        try
          if not fDevices.TryGetValue(key, device) then
          begin
            device := TUDAPDevice.Create(response);
            fDevices.Add(key, device);
          end
          else device.Update(response);
        finally
          TMonitor.Exit(fDevices);
        end;
        if (response.ucp_method=UCP_METHOD_ADV_DISCOVER) or (response.ucp_method=UCP_METHOD_DISCOVER) then
        begin
          // auto respond to discover messages
          sendCommand(PORT_UDAP, TUDAPMessage.Create.GetIP(response.src_address.address_mac).buffer);
          sendCommand(PORT_UDAP, TUDAPMessage.Create.GetData(response.src_address.address_mac).buffer);
        end;
      end;
    end;
  end
end;

procedure TUDAPControl.ShowParameter(aDevice: TUDAPDevice; const aParameterName: string);
var
  value: string;
begin
  if aDevice.parameters.TryGetValue(aParameterName, value)
  then WriteLn('   '+aParameterName+': '+value);
end;

procedure TUDAPControl.ListDevices;
var
  adp: TPair<TUDAPAddress, TUDAPDevice>;
  i: Integer;
begin
  TMonitor.Enter(fDevices);
  try
    i := 0;
    for adp in fDevices do
    begin
      i := i+1;
      WriteLn(i.ToString+' '+adp.Key.toString+': '+ParameterValue(adp.Value, 'DeviceName'));
      ShowParameter(adp.Value, 'UseDHCP');
      ShowParameter(adp.Value, 'lan_network_address');
      ShowParameter(adp.Value, 'lan_subnet_mask');
      ShowParameter(adp.Value, 'lan_gateway');
      ShowParameter(adp.Value, 'squeezecenter_address');
    end;
    WriteLn;
  finally
    TMonitor.Exit(fDevices);
  end;
end;

function TUDAPControl.ParameterValue(aDevice: TUDAPDevice; const aParameterName: string): string;
begin
  if not aDevice.parameters.TryGetValue(aParameterName, Result)
  then Result := '';
end;

function TUDAPControl.sendCommand(aPort: Integer; const aBuffer: TArray<byte>): Boolean;
var
  broadcastAddress: sockaddr_in;
  res: Integer;
begin
  FillChar(broadcastAddress, SizeOf(broadcastAddress), $FF);
  broadcastAddress.sin_family := AF_INET;
  broadcastAddress.sin_port := htons(aPort);
  //WriteLn('sent: ('+length(aBuffer).ToString+') '+bytesToHex(aBuffer));
  TMonitor.Enter(Self);
  try
    res := sendto(fSocket, aBuffer[0], length(aBuffer), 0, @broadcastAddress, SizeOf(broadcastAddress));
  finally
    TMonitor.Exit(Self);
  end;
  Result := res<>SOCKET_ERROR;
end;

procedure TUDAPControl.SendDiscover;
begin
  if not sendCommand(PORT_UDAP, TUDAPMessage.Create.Discover.buffer)
  then WriteLn('## Could not send discover request ('+WSAGetLastError.ToString()+')');
end;

procedure TUDAPControl.ShowDetails;
var
  adp: TPair<TUDAPAddress, TUDAPDevice>;
  keys: TArray<string>;
  key: string;
begin
  TMonitor.Enter(fDevices);
  try
    for adp in fDevices do
    begin
      WriteLn(adp.Key.toString);
      keys := adp.Value.parameters.Keys.ToArray;
      TArray.Sort<string>(keys, TCustomStringComparer.Create);
      for key in keys do
      begin
        WriteLn('   '+Key+': '+adp.Value.parameters[key]);
      end;
      WriteLn;
    end;
  finally
    TMonitor.Exit(fDevices);
  end;
end;

var
  WSAData: TWSAData;
  udap: TUDAPControl;
  s: string;
begin
  try
    WSAStartup($0202, WSAData);
    try
      udap := TUDAPControl.Create;
      try
        WriteLn('Sent discover message');
        udap.SendDiscover;
        repeat
          Write('> ');
          ReadLn(s);
          // DIscover
          if s.ToLower.StartsWith('di') then
          begin
            WriteLn('Sent discover message');
            udap.SendDiscover;
          end
          // DEtails
          else if s.ToLower.StartsWith('de')
          then udap.ShowDetails
          // List
          else if s.ToLower.StartsWith('l')
          then udap.ListDevices
          else if s.ToLower.StartsWith('h') or (s='?') then
          begin
            WriteLn;
            WriteLn('commands (upper case part is minimal characters, command itself is case insensitive)');
            WriteLn('   DIscover - send a discover signal on the network');
            WriteLn('   List - list known devices');
            WriteLn('   DEtails - show details on known devices');
            WriteLn('   Quit or Exit- exit the application');
            WriteLn;
            WriteLn('   Help or ?- this list');
            WriteLn;
          end
          else WriteLn('## could not decode command, type Help for options');
        until s.ToLower.StartsWith('q') or s.ToLower.StartsWith('e');
      finally
        udap.Free;
      end;
    finally
      WSACleanup;
    end;
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.
