<#
.SYNOPSIS
	Update software to latest online version
	Takes infos from csv file called update.config.csv
.DESCRIPTION
	Author: Nicolas Dietschy
	License:
	Required Dependencies:
     - Firefox
     - Powershell Selenium module (Install-Module -Name Selenium -RequiredVersion 3.0.1) https://www.powershellgallery.com/packages/Selenium/3.0.1
     - Admin rights
	Optional Dependencies: None
    Warning !
    downloadPath variable should be set on firefox default download path, if not set, script is buggy
#>

$disableInstall = $false
$DebugPreference = "Continue" #print debug informations choose Continue or SilentlyContinue
$i = 0

if(!(Get-Command -Module selenium)){
    Write-Error "Module selenium is absent, please install it"
    break
}

if($array){Clear-Variable array}

$updaterConfigFile = Import-CSV -Delimiter ";" -Path $PSScriptRoot/updater.config.csv
$logFile = "$PSScriptRoot\updater.log"
$downloadPath = "C:\Users\$env:USERNAME\Downloads"

# If Get-ItemProperty failed try getting programms via reg command
Function Get-InstalledPrograms(){
    Write-Output "Get-InstalledPrograms"
    if(Test-Path "$PSScriptRoot\32.reg"){Remove-Item $PSScriptRoot\32.reg}
    if(Test-Path "$PSScriptRoot\64.reg"){Remove-Item $PSScriptRoot\64.reg}

    try{
        reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall $PSScriptRoot\32.reg ; reg export HKEY_LOCAL_MACHINE\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall $PSScriptRoot\64.reg
    } catch {
        Write-Output "Cannot get programms from registry"
        $_
        break
    }

    Start-Sleep -Seconds 1

    $fichier = Get-Content $PSScriptRoot\32.reg,$PSScriptRoot\64.reg ; $programArray=@()

    foreach($line in $fichier){
        if($line.StartsWith('[')){ $object = New-Object –TypeName psobject }
        elseif($line.StartsWith('"DisplayName')){$object | Add-Member –MemberType NoteProperty -Name "DisplayName"  –Value "$($($line.Split('=')[-1]).replace('"',''))" -ErrorAction SilentlyContinue }
        elseif($line.StartsWith('"DisplayVersion')){ $object | Add-Member –MemberType NoteProperty -Name "DisplayVersion"  –Value "$($($line.Split('=')[-1]).replace('"',''))" -ErrorAction SilentlyContinue }
        elseif($line -eq ""){ if($object.DisplayName -match "[a-z]"){ $programArray += $object }}
    }
    return $($programArray | Sort-Object)
}

Function checkOnlineVersion {param($onlineVersion)
    Write-Log -message "onlineVersion : $onlineVersion"

    if ($onlineVersion -match "[0-9]"){
        Write-Output "Online version $onlineVersion"
        return $true
    } else {
        Write-Output "Online version $onlineVersion"
        return $false
    }
}

Function Write-Log(){ param($message)
    $date = Get-Date -Format "%H:%m:%s dd/MM/yyyy"
    Add-Content -Value "$env:COMPUTERNAME $date $message" -Path "$logFile" -ErrorAction SilentlyContinue
}

Function Install-Software(){ param($executable, $parameter, $process)
    try{
        Write-Output "executable : $executable `t parameter : $parameter `t process : $process `t"

        if(Get-Process "$process" -ErrorAction SilentlyContinue){
            Write-Output "$process is already running`nPlease close it"
        } else{
            $install = Start-Process $executable -ArgumentList "$parameter" -Wait -PassThru
            Write-Log -message "Installation of $($_.displayName) -> $executable $parameter"
            Write-Log -message "Exit code : $($install.ExitCode)"
        }
    }catch {
        $_
    }
}

Function LaunchSelenium(){param($url, $timeout, $pattern)
    $j = 0
    Write-Output "GOTO $url"
    Open-SeUrl $url -Driver $Driver
    try{
        foreach ($xpath in $line.xpaths.Split("|")){
            $tabNumber=$driver.WindowHandles.count
            Invoke-SeClick -Element $(Get-SeElement -XPath "$xpath" -Driver $driver)

            if($tabNumber -lt $driver.WindowHandles.count){
                Start-Sleep -Milliseconds 500
                Write-Output "Switching on new tab"
                $handles = $driver.WindowHandles
                Switch-SeWindow -Driver $driver -Window $handles[-1]
            }
        }
    } catch {
        $_
    }

    while($j -lt $timeout){
        # If last downloaded element contains pattern and ends with .exe
        $lastElement = (Get-ChildItem $downloadPath | Sort-Object -Property lastwritetime)[-1]
        if($lastElement.FullName.Contains("$pattern") -and $lastElement.FullName.EndsWith(".exe") ){
            $j = $timeout
        }

        Write-Progress -Activity "$pattern installer absent" -SecondsRemaining ($timeout-$i) -PercentComplete $($i/$timeout*100)
        Start-Sleep -Seconds 2
        $j=$j+2
    }
}

# Get programms list
try {
    $programArray=Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $programArray+=Get-ItemProperty "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Sort-Object -Descending
} catch {
    $programArray=Get-InstalledPrograms
}

try {
    $driver = Start-SeFirefox -Headless
} catch {
    Write-Output "Cannot start driver\n$_"
    break
}

foreach ($line in $updaterConfigFile) {
    if($line.update -eq "TRUE"){
        # Browse PC programm list
        foreach($_ in $programArray){

            # If the software is found
            if($_.displayName -and $_.displayName.contains($($line.soft))){
                Write-Output "`n==============================================================="
                try{
                    $pattern = $($line.soft) -replace "\s",""
                    Write-Output "$($_.displayName) @ $($_.DisplayVersion)" ; $PCversion=$_.DisplayVersion ; Write-Log -message "PC Version of $($_.displayName) : $PCversion"

                    # Get online version
                    $geturl = Invoke-WebRequest $($line.url)
                    $onlineVersion = Invoke-Expression $($line.getVersion)

                    if (!(checkOnlineVersion -onlineVersion $onlineVersion)){
                       Write-Error "Incorrect online version"
                       break
                    } elseif ($PCversion -ne $onlineVersion){
                        Write-Output "PC version obsolete $PCversion < $onlineVersion Download in progress ..."
                        Write-Log -message "PC version obsolete $PCversion < $onlineVersion Download in progress ..."

                        $outFile = "$pattern-"+"$onlineVersion"+".exe"

                        Write-Debug "Downloading : $outFile (outFile)"

                        LaunchSelenium -url $line.url -timeout 120 -pattern "$($line.pattern)"
                        if($i -eq 70){
                            Write-Log -message "Cannot download $($_.displayName)"
                        } else{
                            $outFile=$($($($(Get-ChildItem $downloadPath | Sort-Object -Property lastwritetime)[-1]).name))
                        }

                        if (!$disableInstall) {
                            Install-Software -executable "$downloadPath\$outFile" -parameter "$($line.installParam)" -process "$($line.soft)"
                        }

                        $i++
                    } else {
                        Write-Information "PC already get latest version"
                        Write-Log -message "PC already get latest version of $($_.displayName)"
                    }
                } catch {
                    $e = $_.Exception
                    $line = $_.InvocationInfo.ScriptLineNumber
                    $msg = $e.Message
                    Write-Error "caught exception: $e at $line`n$msg"
                    $_
                    break
                }
            }
        }
    }
}
Write-Debug "Closing Selenium driver ..."
$driver.Quit()

if($i -eq 0) {
    Write-Output "It looks like you're already up to date ! Congrats !"
}