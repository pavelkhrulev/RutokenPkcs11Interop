namespace RutokenPkcs11Interop.Common
{
    public enum TokenManageMode
    {
        SetBluetoothPoweroffTimeout = 0x01,
        SetChannelType = 0x02,
        BluetoothPoweroffTimeoutDefault = 0x00,
        BluetoothPoweroffTimeoutMax = 0x46,
        ChannelTypeUsb = 0x00,
        ChannelTypeBluetooth = 0x01
    }
}
