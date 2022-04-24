$SSIDs = @(
	@{
		Name = "Name1"
		PSK  = "Password1"
	}
	#@{
	#	Name = "Name2"
	#	PSK  = "Password2"
	#}
)

foreach ($SSID in $SSIDs)
{
	$SSIDName = $SSID.Name
	$guid = New-Guid
	$HexArray = $SSIDName.ToCharArray() | foreach-object { [System.String]::Format("{0:X}", [System.Convert]::ToUInt32($_)) }
	$HexSSID = $HexArray -join ""
	@"
<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>$($SSIDName)</name>
    <SSIDConfig>
        <SSID>
            <hex>$($HexSSID)</hex>
            <name>$($SSIDName)</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>$($SSID.PSK)</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
    <MacRandomization xmlns="http://www.microsoft.com/networking/WLAN/profile/v3">
        <enableRandomization>false</enableRandomization>
        <randomizationSeed>1451755948</randomizationSeed>
    </MacRandomization>
</WLANProfile>
"@ | out-file "$($ENV:TEMP)\$guid.SSIDName"
	
	netsh wlan add profile filename="$($ENV:TEMP)\$guid.SSIDName" user=all
	
	remove-item "$($ENV:TEMP)\$guid.SSIDName" -Force
}
