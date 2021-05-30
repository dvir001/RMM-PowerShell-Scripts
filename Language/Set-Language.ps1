function Set-Language-EN_HE
{
	$source = 'https://www.forensit.com/Downloads/Profwiz.msi'
	$dir = 'C:\Windows\Temp'
	$name = 'Win10_LP_En.cab'
	$systemLocale = 'en-US'
	$language = 'en-US'
	$language2 = 'he'
	
	Dism /online /Add-Package /PackagePath:$dir\$name
	Set-WinSystemLocale $systemLocale
	
	$UserLanguageList = New-WinUserLanguageList -Language $language
	$UserLanguageList.Add("$language2")
	Set-WinUserLanguageList -LanguageList $UserLanguageList
}

function Set-Language-HE_EN
{
	$source = 'https://www.forensit.com/Downloads/Profwiz.msi'
	$dir = 'C:\Windows\Temp'
	$name = 'Win10_LP_He.cab'
	$systemLocale = 'he-IL'
	$language = 'he'
	$language2 = 'en-US'
	
	Dism /online /Add-Package /PackagePath:$dir\$name
	Set-WinSystemLocale $systemLocale
	
	$UserLanguageList = New-WinUserLanguageList -Language $language
	$UserLanguageList.Add("$language2")
	Set-WinUserLanguageList -LanguageList $UserLanguageList
}
