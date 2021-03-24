--[=[
name: Hafnium Microsoft Exchange Scanner
filetype: Infocyte Extension
type: Collection
description: | 
    Checks for indicators of compromise related to the March 2021 Exchange Vulns (ProxyLogon) and the Threat Group Hafnium.
    This will use webshell and china chopper webshell yara signatures to scan the wwwroot folder.
    In addition, it will also grab relevant logs that Microsoft recommends you review using Powershell commands provided by Microsoft.
    Beacons and other memory-only footholds will be found natively with Infocyte's memory scans (you will see memory injects in common Windows processes)
    https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
    https://threatpost.com/microsoft-exchange-zero-day-attackers-spy/164438/
author: Infocyte
guid: ebaffffc-ba24-4d12-9c1a-928116523e89
created: 2021-03-05
updated: 2021-03-06

# Global variables
globals:
- quick_scan:
    description: Some scans can cause performance issues and timeouts to be hit - this restricts the scan to certain date ranges
    type: boolean
    default: true

- wwwrootpath:
    description: wwwroot path
    type: string
    default: C:\\inetpub\\wwwroot

# Runtime arguments
args:

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

quick_scan = hunt.global.boolean("quick_scan", false, true)
wwwrootpath = hunt.global.boolean("wwwrootpath", false, "C:\\inetpub\\wwwroot")

rules = [=[
rule webshell_aspx_simpleseesharp : Webshell Unclassified
{
    meta:
        author= "threatintel@volexity.com"
        date= "2021-03-01"
        description= "A simple ASPX Webshell that allows an attacker to write further files to disk."
        hash= "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"

    strings:
        $header= "<%@ Page Language=\"C#\" %>"
        $body= "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

    condition:
        $header at 0 and
        $body and
        filesize < 1KB
}
rule webshell_aspx_reGeorgTunnel : Webshell Commodity
{
    meta:
        author= "threatintel@volexity.com"
        date= "2021-03-01"
        description= "variation on reGeorgtunnel"
        hash= "406b680edc9a1bb0e2c7c451c56904857848b5f15570401450b73b232ff38928"
        reference= "https://github.com/sensepost/reGeorg/blob/master/tunnel.aspx"

    strings:
        $s1= "System.Net.Sockets"
        $s2= "System.Text.Encoding.Default.GetString(Convert.FromBase64String(StrTr(Request.Headers.Get"
        $t1 = ".Split('|')"
        $t2= "Request.Headers.Get"
        $t3= ".Substring("
        $t4= "new Socket("
        $t5= "IPAddress ip;"

    condition:
        all of ($s*) or
        all of ($t*)
}

rule ChinaChopper_Generic {
	meta:
		description = "China Chopper Webshells - PHP and ASPX"
		license = "https://creativecommons.org/licenses/by-nc/4.0/"
		author = "Florian Roth"
		reference = "https://www.fireeye.com/content/dam/legacy/resources/pdfs/fireeye-china-chopper-report.pdf"
		date = "2015/03/10"
	strings:
		$aspx = /%@\sPage\sLanguage=.Jscript.%><%eval\(Request\.Item\[.{,100}unsafe/
		$php = /<?php.\@eval\(\$_POST./
	condition:
		1 of them
}

rule WEBSHELL_ASP_Embedded_Mar21_1 {
   meta:
      description = "Detects ASP webshells"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2021-03-05"
      score = 85
   strings:
      $s1 = "<script runat=\"server\">"
      $s2 = "new System.IO.StreamWriter(Request.Form["
      $s3 = ".Write(Request.Form["
   condition:
      filesize < 100KB and all of them
}

rule APT_WEBSHELL_HAFNIUM_SecChecker_Mar21_1 {
   meta:
      description = "Detects HAFNIUM SecChecker webshell"
      author = "Florian Roth"
      reference = "https://twitter.com/markus_neis/status/1367794681237667840"
      date = "2021-03-05"
      hash1 = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0"
   strings:
      $x1 = "<%if(System.IO.File.Exists(\"c:\\\\program files (x86)\\\\fireeye\\\\xagt.exe" ascii
      $x2 = "\\csfalconservice.exe\")){Response.Write( \"3\");}%></head>" ascii fullword
   condition:
      uint16(0) == 0x253c and
      filesize < 1KB and
      1 of them or 2 of them
}

rule APT_HAFNIUM_Forensic_Artefacts_Mar21_1 {
   meta:
      description = "Detects forensic artefacts found in HAFNIUM intrusions"
      author = "Florian Roth"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
      date = "2021-03-02"
   strings:
      $s1 = "lsass.exe C:\\windows\\temp\\lsass" ascii wide fullword
      $s2 = "c:\\ProgramData\\it.zip" ascii wide fullword
      $s3 = "powercat.ps1'); powercat -c" ascii wide fullword
   condition:
      1 of them
}

rule APT_WEBSHELL_HAFNIUM_Chopper_WebShell: APT Hafnium WebShell {
   meta:
      description = "Detects Chopper WebShell Injection Variant (not only Hafnium related)"
      author = "Markus Neis,Swisscom"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
   strings:
      $x1 = "runat=\"server\">"

      $s1 = "<script language=\"JScript\" runat=\"server\">function Page_Load(){eval(Request"
      $s2 = "protected void Page_Load(object sender, EventArgs e){System.IO.StreamWriter sw = new System.IO.StreamWriter(Request.Form[\"p\"] , false, Encoding.Default);sw.Write(Request.Form[\"f\"]);"
      $s3 = "<script language=\"JScript\" runat=\"server\"> function Page_Load(){eval (Request[\""    
   condition:
      filesize < 10KB and $x1 and 1 of ($s*) 
}

rule APT_WEBSHELL_Tiny_WebShell : APT Hafnium WebShell {
   meta:
      description = "Detects WebShell Injection"
      author = "Markus Neis,Swisscom"
      hash = "099c8625c58b315b6c11f5baeb859f4c"
      date = "2021-03-05"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
   strings:
      $x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"

      $s1 = "=Request.Form(\""
      $s2 = "eval("
   condition:
      filesize < 300 and all of ($s*) and $x1
} 

rule HKTL_PS1_PowerCat_Mar21 {
   meta:
      description = "Detects PowerCat hacktool"
      author = "Florian Roth"
      reference = "https://github.com/besimorhino/powercat"
      date = "2021-03-02"
      hash1 = "c55672b5d2963969abe045fe75db52069d0300691d4f1f5923afeadf5353b9d2"
   strings:
      $x1 = "powercat -l -p 8000 -r dns:10.1.1.1:53:c2.example.com" ascii fullword
      $x2 = "try{[byte[]]$ReturnedData = $Encoding.GetBytes((IEX $CommandToExecute 2>&1 | Out-String))}" ascii fullword

      $s1 = "Returning Encoded Payload..." ascii
      $s2 = "$CommandToExecute =" ascii fullword
      $s3 = "[alias(\"Execute\")][string]$e=\"\"," ascii
   condition:
      uint16(0) == 0x7566 and
      filesize < 200KB and
      1 of ($x*) or 3 of them
}

rule HKTL_Nishang_PS1_Invoke_PowerShellTcpOneLine {
   meta:
      description = "Detects PowerShell Oneliner in Nishang's repository"
      author = "Florian Roth"
      reference = "https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1"
      date = "2021-03-03"
      hash1 = "2f4c948974da341412ab742e14d8cdd33c1efa22b90135fcfae891f08494ac32"
   strings:
      $s1 = "=([text.encoding]::ASCII).GetBytes((iex $" ascii wide
      $s2 = ".GetStream();[byte[]]$" ascii wide
      $s3 = "New-Object Net.Sockets.TCPClient('" ascii wide
   condition:
      all of them
}

rule WEBSHELL_ASPX_SportsBall : Webshell {
   meta:
      author = "threatintel@volexity.com"
      date = "2021-03-01"
      description = "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
      hash = "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"
      reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
   strings:
      $uniq1 = "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
      $uniq2 = "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="

      $var1 = "Result.InnerText = string.Empty;"
      $var2 = "newcook.Expires = DateTime.Now.AddDays("
      $var3 = "System.Diagnostics.Process process = new System.Diagnostics.Process();"
      $var4 = "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
      $var5 = "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
      $var6 = "<input type=\"submit\" value=\"Upload\" />"
   condition:
      any of ($uniq*) or
      all of ($var*)
}

rule WEBSHELL_CVE_2021_27065_Webshells {
   meta:
      description = "Detects web shells dropped by CVE-2021-27065. All actors, not specific to HAFNIUM. TLP:WHITE"
      author = "Joe Hannon, Microsoft Threat Intelligence Center (MSTIC)"
      date = "2021-03-05"
      reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
   strings:
      $script1 = "script language" ascii wide nocase
      $script2 = "page language" ascii wide nocase
      $script3 = "runat=\"server\"" ascii wide nocase
      $script4 = "/script" ascii wide nocase
      $externalurl = "externalurl" ascii wide nocase
      $internalurl = "internalurl" ascii wide nocase
      $internalauthenticationmethods = "internalauthenticationmethods" ascii wide nocase
      $extendedprotectiontokenchecking = "extendedprotectiontokenchecking" ascii wide nocase
   condition:
      filesize < 10KB and any of ($script*) and ($externalurl or $internalurl) and $internalauthenticationmethods and $extendedprotectiontokenchecking
}
]=]

--[=[ SECTION 2: Functions ]=]

function is_executable(path)
    --[=[
        Check if a file is an executable (PE or ELF) by magic number. 
        Input:  [string]path
        Output: [bool] Is Executable
    ]=] 
    magicnumbers = {
        "MZ",
        ".ELF"
    }
    local f,msg = io.open(path, "rb")
    if not f then
        --hunt.debug(msg)
        return nil
    end
    local bytes = f:read(4)
    if bytes then
        -- print(bytes)
        for _,n in pairs(magicnumbers) do
            magicheader = string.find(bytes, n)
            if magicheader then
                -- print(string.byte(magicheader))
                f:close()
                return true
            end
        end
        f:close()
        return false
    end
end

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
end

function get_fileextension(path)
    match = path:match("^.+(%..+)$")
    return match
end

function yara_scan(paths, signatures) 
    --[=[
        Scans list of files with yara signatures and returns list of matched file paths 
        Will also make a log entry with each match. 
        Input:  [table]paths
                [string]signatures
        Output: [bool]match
                [table]matches { sha1, path, signature }
    ]=]

    -- Input validation
    if type(paths) ~= "table" or type(signatures) ~= "string" then
        hunt.error(f"[yara_scan] Invalid format for inputs to function. [table]paths=${type(paths)}, [string]signatures=${type(signatures)}")
    end 
    str = string.gsub(signatures, '[ \t]+%f[\r\n%z]', '') -- strip whitespace
    if not str or str == '' then
        hunt.warn("No signatures provided")
        return nil, {}
    end
    
    unique_paths = {} -- add to keys of list to easily unique paths
    matches = {}
    -- Load Yara rules
    yara = hunt.yara.new()
    yara:add_rule(signatures)

    -- Scan all paths with Yara signatures
    n=1
    for i, path in pairs(paths) do
        -- dedup paths
        if unique_paths[path] then
            goto continue
        end
        if verbose then hunt.log(f"[${n}] Scanning ${path} with ${levels[level]} signatures") end
        for _, signature in pairs(yara:scan(path)) do
            if not hash then
                hash = hunt.hash.sha1(path)
            end
            hunt.verbose(f"Matched yara rule [${levels[level]}]${signature} on: ${path} <${hash}>")
            m = {}
            m["path"] = path
            m["sha1"] = hash
            m["signature"] = signature
            table.insert(matches, m)
        end
        unique_paths[path] = true
        n=n+1
        hash = nil
        if test and n > 3 then
            return #matches > 0, matches
        end
        ::continue::
    end
    return #matches > 0, matches
end


--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.log(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

-- Scan
level = 10 -- threat level (10 is not defined)
levels = {}
levels[1] = "BAD"
levels[2] = "SUSPICIOUS"
levels[3] = "INFO"

-- Get Exchange Install Path
hunt.log("Getting Exchange Install Path...")
exchange_path, err = hunt.env.run_powershell([[
    return (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
]])
if err ~= "" then
    hunt.error("Error getting Microsoft Exchange Path")
    hunt.error(err)
end
if exchange_path == nil or exchange_path == "" then
    hunt.warn("Microsoft Exchange 2013+ is not installed on this host (or Powershell is disabled by a 3rd party tool). Skipping Exchange Checks.")
    hunt.status.good()
    --return
else
    hunt.log(f"Microsoft Exchange Found. Install Path: ${exchange_path}")
end

-- Get default Web Site wwwroot folder
out, err = hunt.env.run_powershell([[
try { (Get-ItemProperty HKLM:\Software\Microsoft\INetStp -Name "PathWWWRoot" -ea stop).PathWWWRoot 
} catch [System.Management.Automation.ItemNotFoundException] { $_.Exception.Message }
]])
if err ~= "" then 
    hunt.error(err)
else
    -- If it can't find it, it'll stay with the default
    if not string.find(out, "Cannot find path") then
        -- Need to test this more, not working all the time.
        wwwrootpath = out
    else
        hunt.error("Could not get wwwrootpath from registry (HKLM:\\Software\\Microsoft\\INetStp\\PathWWWRoot). Using default.")
    end
    hunt.log(f"Default Web Site wwwroot folder: ${wwwrootpath}")
end

paths = {}

hunt.log("Scanning aspx files within wwwroot & exchange frontend folders for webshells")
if quick_scan then 
    depth = 2
else
    depth = 6
end
opts = {
    "files",
    f"recurse=${depth}"
}
-- wwwrootpath = "C:\\inetpub\\wwwroot"
for _, path in pairs(hunt.fs.ls(f"${wwwrootpath}\\aspnet_client", f"${exchange_path}\\Frontend", opts)) do
    if get_fileextension(path:name()) == ".aspx" then
        p = path:path()
        fn = get_filename(path:name()) or ""
        hunt.log(f"Found .aspx file: ${p}")
        if string.len(fn) == 13 then
            level = 2
            hunt.warn(f"WARNING: aspx file '${fn}' file found with 8 characters (commonly used by HAFNIUM exploits but not by itself malicious)")
        end
        table.insert(paths, path:path())
    end
end

if #paths > 0 then 
    hunt.log(f"Found ${#paths} .aspx files -- scanning for webshells")
else
    hunt.log(f"Could not find .aspx files within '${wwwrootpath}\\aspnet_client\\*' or '${exchange_path}\\Frontend\\*' (recursion three levels deep) -- skipping scanning")
end

match, matches = yara_scan(paths, rules) 
if match then
    -- print("Found matches!")
    level = 1
    for _, m in pairs(matches) do
        hunt.log(f"Matched yara rule [${levels[level]}]${m['signature']} on: ${m['path']} <${m['hash']}>")
    end
else
    hunt.log("No matches found with yara rules.")
end


-- Add bad and suspicious files to Artifacts list for analysis
n = 0
for path,i in pairs(matches) do
    if test and n > 3 then
        break
    end
    -- Create a new artifact
    artifact = hunt.survey.artifact()
    artifact:exe(path)
    artifact:type("Hafnium Extension")
    hunt.survey.add(artifact)
    n = n + 1
end

hunt.log("\n")
hunt.log("CVE-2021-26855: Grabbing relevant Exchange HttpProxy logs via Powershell")
hunt.log("Note: This search can take a long time. It is currently set to timeout after 5 minutes.")
hunt.log([=[-- CVE-2021-26855 exploitation can be detected via the following Exchange HttpProxy logs:
-- These logs are located in the following directory: %PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\HttpProxy
-- Exploitation can be identified by searching for log entries where the AuthenticatedUser is empty and the AnchorMailbox contains the pattern of ServerInfo~*/*
-------------------------------------------------------------------]=])
out, err = hunt.env.run_powershell([[
    $exchangePath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ea 0).MsiInstallPath
    if ($null -eq $exchangePath) { $exchangePath = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15"}
    try {
        $sw = New-Object System.Diagnostics.Stopwatch
        $sw.Start()
        $Hits = [System.Collections.ArrayList]@()
        $files = [System.Array](Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy" -Filter '*.log' -ea 0 | Select FullName -ExpandProperty FullName)
        For ( $i = 0; $i -lt $files.Count; ++$i ) {
            if ($sw.ElapsedMilliseconds -lt 60*5*1000) {
                if ((Test-Path $files[$i]) -AND (Select-String -Path $files[$i] -Pattern "ServerInfo~" -Quiet)) {
                    Import-Csv -Path $files[$i] -ea 0 | Where-Object { 
                        $_.AnchorMailbox -Like 'ServerInfo~*/*' -and $_.AnchorMailbox -notlike 'ServerInfo~*/autodiscover*' -and $_.AnchorMailbox -notlike 'ServerInfo~localhost*/*' 
                    } | Select-Object -Property DateTime, RequestId, ClientIPAddress, UrlHost, UrlStem, RoutingHint, UserAgent, AnchorMailbox, HttpStatus | ForEach-Object {
                        $Hits += $_
                    }
                }
            }
        }
        if ($Hits.count -gt 0) {
            $OutString = "CVE-2021-26855 Log Hits: $($Hits.count)`n"
            $OutString += $Hits | Out-String
        }
        return $OutString
    }
    catch [System.Management.Automation.ItemNotFoundException] { return "ERROR: $($_.Exception.Message)" }
]])
if (err ~= nil and err ~= "") or out:find("ERROR:") then 
    hunt.error(err)
elseif out then
    if out == nil or out == "" then
        hunt.log("RESULT: Nothing suspicious detected.") 
    else
        hunt.log(out)
        if level > 2 then
            level = 2
        end
    end
end

hunt.log("\n")
hunt.log("CVE-2021-26858: Grabbing relevant Exchange log files via Powershell")
hunt.log([=[-- If activity is detected, the logs specific to the application specified in the AnchorMailbox path can be used to help determine what actions were taken.
-- These logs are located in the %PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging directory.

-- CVE-2021-26858 exploitation can be detected via the Exchange log files:
-- C:\Program Files\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog
-- Files should only be downloaded to the %PROGRAMFILES%\Microsoft\Exchange Server\V15\ClientAccess\OAB\Temp directory
-- In case of exploitation, files are downloaded to other directories (UNC or local paths)
-------------------------------------------------------------------]=])
out, err = hunt.env.run_powershell([[
    $exchangePath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ea 0).MsiInstallPath
    if ($null -eq $exchangePath) { $exchangePath = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15"}
    try {
        $downloadPaths = [System.Collections.ArrayList]@()
        $files = [System.Array](Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" -ea 0 | Select-String "Download failed and temporary file" -List | Select-Object -ExpandProperty Path)
        for ( $i = 0; $i -lt $files.Count; $i++) {
            $loginstance = Select-String -Path $files[$i] -Pattern "Download failed and temporary file"
            foreach ($logLine in $loginstance) {
                $path = ([String]$logLine | Select-String -Pattern 'Download failed and temporary file (.*?) needs to be removed').Matches.Groups[1].value
                if ($null -ne $path -and (-not ($path.StartsWith("'$exchangePath" + "ClientAccess\OAB", "CurrentCultureIgnoreCase")))) {
                    [Void]$downloadPaths.Add( [String]$path )
                }
            }
        }
        return $downloadPaths
    } 
    catch [System.Management.Automation.ItemNotFoundException] { return "ERROR: $($_.Exception.Message)"  }
]])
if (err ~= nil and err ~= "") or out:find("ERROR:") then 
    hunt.error(err)
elseif out then
    if out == nil or out == "" then
        hunt.log("RESULT: Nothing suspicious detected in OABGeneratorLog.") 
    else
        for s in out:gmatch("[^\r\n]+") do
            -- Create a new artifact
            artifact = hunt.survey.artifact()
            artifact:exe(s)
            artifact:type("Hafnium Extension")
            hunt.survey.add(artifact)
            n = n + 1
        end
        hunt.log("Downloaded files found in suspicious locations. Added the following to Artifacts:")
        hunt.log(out)
        if level > 2 then
            level = 2
        end
    end
end

hunt.log("\n")
hunt.log("CVE-2021-26857: Grabbing MSExchange Unified Messaging event logs via Powershell")
if quick_scan then
    startdate = [[$startdate = "02/27/21";
    ]]
    hunt.warn("QuickScan Set: Setting earliest MSExchange Unified Messaging event log pull to 02/27/21. This command has performance issues and will likely hit timeouts. If you want to go back further, create a global boolean variable called 'quick_scan' and set it to false.")
else 
    startdate = [[$startdate = "06/01/2020";
    ]]
end
hunt.log([=[-- CVE-2021-26857 exploitation can be detected via the Windows Application event logs
        -- Exploitation of this deserialization bug will create Application events with the following properties:
        -- Source: MSExchange Unified Messaging
        -- EntryType: Error
        -- Event Message Contains: System.InvalidCastException
        -------------------------------------------------------------------]=])
out, err = hunt.env.run_powershell(startdate..[[
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = 'Application'
        ProviderName = 'MSExchange Unified Messaging'
        Level        = '2'
        StartTime    = $startdate
    } -ea stop | Where-Object Message -Like "*System.InvalidCastException*"
    if ($events.count > 0) {
        return $events | fl | Out-String
    } else { return }
}
catch { return "ERROR: MSExchange Unified Messaging provider is not present or events not found in the Application Event log" }
]])
if (err ~= nil and err ~= "") or out:find("ERROR:") then 
    hunt.error(err)
elseif out then
    if out == nil or out == "" then
        hunt.log("RESULT: Nothing suspicious detected in MSExchange Unified Messaging event logs.") 
    else
        hunt.log(out)
        if level > 2 then
            level = 2
        end
    end
end

hunt.log("\n")
hunt.log([=[CVE-2021-27065: Grabbing relevant logs (V15\Logging\ECP\Server) via Powershell]=])
hunt.log([=[-- CVE-2021-27065 exploitation can be detected via the following Exchange log files:
-- C:\Program Files\Microsoft\Exchange Server\V15\Logging\ECP\Server
-- All Set-<AppName>VirtualDirectory properties should never contain scripts. InternalUrl and ExternalUrl should only be valid Uris.
-------------------------------------------------------------------]=])
out, err = hunt.env.run_powershell([[
$exchangePath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ea 0).MsiInstallPath
if ($null -eq $exchangePath) { $exchangePath = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15"}
try {
    $setVDirMaliciousUrlLogs = Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction 0 | Select-String "Set-.+VirtualDirectory.+?(?=Url).+<\w+.*>(.*?)<\/\w+>.+?(?=VirtualDirectory)" -List | Select-Object -ExpandProperty Path
    return $setVDirMaliciousUrlLogs
} catch [System.Management.Automation.ItemNotFoundException] { return "ERROR: $($_.Exception.Message)" }
]])
if (err ~= nil and err ~= "") or out:find("ERROR:") then 
    hunt.error(err)
elseif out then
    if out == nil or out == "" then
        hunt.log("RESULT: Nothing suspicious detected in ECP\\Server logs.") 
    else
        hunt.log("[CVE-2021-27065] ECP logs had suspicious URLs:\n")
        hunt.log(out)
        if level > 2 then
            level = 2
        end
    end
end
out, err = hunt.env.run_powershell([[
    $exchangePath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ea 0).MsiInstallPath
    if ($null -eq $exchangePath) { $exchangePath = "$env:PROGRAMFILES\Microsoft\Exchange Server\V15"}
    try { 
        $setVDirMaliciousUrlLogs = [System.Collections.ArrayList]@()
        $files = [System.Array](Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -Filter '*.log' -ea 0 | Select FullName -ExpandProperty FullName)
        For ( $i = 0; $i -lt $files.Count; ++$i ) {
            if ((Get-ChildItem $files[$i] -ErrorAction SilentlyContinue | Select-String -Pattern "ServerInfo~").Count -gt 0) {
                $hits = @(Import-Csv -Path $files[$i] -ErrorAction SilentlyContinue | Where-Object { $_.AnchorMailbox -Like 'ServerInfo~*/*Reset*VirtualDirectory#' -and $_.HttpStatus -eq 200 } |
                    Select-Object -Property $outProps)
                if ($hits.Count -gt 0) {
                    $hits | ForEach-Object {
                        [Void]$resetVDirHits.Add( $_ )
                    }
                }
            }
        }
        return $resetVDirHits
    } catch [System.Management.Automation.ItemNotFoundException] { return "ERROR: $($_.Exception.Message)" }
]])
if (err ~= nil and err ~= "") or out:find("ERROR:") then 
    hunt.error(err)
elseif out then
    if out == nil or out == "" then
        hunt.log("RESULT: Nothing suspicious detected in HttpProxy\\Ecp logs.") 
    else
        hunt.log("[CVE-2021-27065] Webshell possibly downloaded in file system. Reset-VirtualDirectory entries:\n")
        hunt.log(out)
        if level > 2 then
            level = 2
        end
    end
end


out, err = hunt.env.run_powershell([=[
function Get-AgeInDays {
    param ( $dateString )
    if ( $dateString -and $dateString -as [DateTime] ) {
        $CURTIME = Get-Date
        $age = $CURTIME.Subtract($dateString)
        return $age.TotalDays.ToString("N1")
    }
    return ""
}
[PSCustomObject]@{
    Oabgen           = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\OABGeneratorLog" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    Ecp              = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\ECP\Server\*.log" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    AutodProxy       = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Autodiscover" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    EasProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Eas" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    EcpProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ecp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    EwsProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Ews" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    MapiProxy        = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Mapi" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    OabProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Oab" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    OwaProxy         = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\Owa" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    OwaCalendarProxy = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\OwaCalendar" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    PowershellProxy  = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\PowerShell" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
    RpcHttpProxy     = (Get-AgeInDays (Get-ChildItem -Recurse -Path "$exchangePath\Logging\HttpProxy\RpcHttp" -ErrorAction SilentlyContinue | Sort-Object CreationTime | Select-Object -First 1).CreationTime)
} | Out-String
]=])
hunt.log("\n")
hunt.log("Log Ages (Days):")
hunt.log([=[-- Log Ages (Days):
-------------------------------------------------------------------]=])
hunt.log(out)

-- Set threat status
if level == 1 then
    result = "Bad"
    hunt.status.bad()
elseif level == 2 then
    result = "Suspicious"
    hunt.status.suspicious()
elseif level == 3 then
    result = "Low Risk"
    hunt.status.low_risk()
else
    result = "Good"
    hunt.status.good()
end

hunt.log("\n")
hunt.log(f"Scan completed. Result=${result}.")
if n > 0 then 
    hunt.log("Added ${n} paths (all bad and suspicious matches) to Artifacts for processing and retrieval.")
end
hunt.log("NOTE: If powershell is disabled by a third party tool, the results for log pulls will be blank.")