--[=[
name: Hafnium Microsoft Exchange Scanner
filetype: Infocyte Extension
type: Collection
description: | 
    Checks for indicators of compromise related to the March 2021 Exchange Vulns and the Threat Group Hafnium.
    Beacons and other memory-only footholds will be found natively with Infocyte's memory scans (you will see memory injects in common Windows processes)
    https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/
    https://threatpost.com/microsoft-exchange-zero-day-attackers-spy/164438/
author: Infocyte
guid: ebaffffc-ba24-4d12-9c1a-928116523e89
created: 2021-03-05
updated: 2021-03-05

# Global variables
globals:

# Runtime arguments
args:

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])


-- max file size to scan (China chopper is 4kb)
max_size = 8000

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

rule webshell_aspx_sportsball : Webshell
{
    meta:
        author= "threatintel@volexity.com"
        date= "2021-03-01"
        description= "The SPORTSBALL webshell allows attackers to upload files or execute commands on the system."
        hash= "2fa06333188795110bba14a482020699a96f76fb1ceb80cbfa2df9d3008b5b0a"

    strings:
        $uniq1= "HttpCookie newcook = new HttpCookie(\"fqrspt\", HttpContext.Current.Request.Form"
        $uniq2= "ZN2aDAB4rXsszEvCLrzgcvQ4oi5J1TuiRULlQbYwldE="
        $var1= "Result.InnerText = string.Empty;"
        $var2= "newcook.Expires = DateTime.Now.AddDays("
        $var3= "System.Diagnostics.Process process = new System.Diagnostics.Process()"
        $var4= "process.StandardInput.WriteLine(HttpContext.Current.Request.Form[\""
        $var5= "else if (!string.IsNullOrEmpty(HttpContext.Current.Request.Form[\""
        $var6= "<input type=\"submit\" value=\"Upload\" />"

    condition:
        any of ($uniq*) or
        all of ($var*)
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
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")

paths = {}

opts = {
    "files",
    f"size<=${max_size}kb", -- any file below this size
    "recurse=2" -- depth of 1
}


hunt.log("Scanning aspx scripts within wwwroot with yara")
for _, path in pairs(hunt.fs.ls("C:\\inetpub\\wwwroot\\aspnet_client", opts)) do
    if get_fileextension(path:path()) == "aspx" then
        table.insert(paths, path:path())
    end
end

-- Scan
level = 0 -- threat level (0 is not defined)
all_matches = {}
levels = {}
levels[1] = "BAD"
levels[2] = "SUSPICIOUS"
levels[3] = "INFO"

hunt.log(f"Scanning ${#paths} paths with yara rules")
match, matches = yara_scan(paths, rules) 
if match then
    hunt.log("Found matches!")
    level = 1
    all_matches = table.concat(all_matches,matches)
    for _, m in pairs(matches) do
        hunt.log(f"Matched yara rule [${levels[level]}]${m['signature']} on: ${m['path']} <${m['hash']}>")
    end
else
    hunt.log("No matches found with file rules!")
end


-- Add bad and suspicious files to Artifacts list for analysis
n = 0
for path,i in pairs(all_matches) do
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



hunt.log("CVE-2021-26855: Grabbing relevant Exchange HttpProxy logs via Powershell")
out, err = hunt.env.run_powershell([[Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox]])
if err then 
    hunt.error(err)
else 
    hunt.log([=[-- CVE-2021-26855 exploitation can be detected via the following Exchange HttpProxy logs:
    -- These logs are located in the following directory: %PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\HttpProxy
    -- Exploitation can be identified by searching for log entries where the AuthenticatedUser is empty and the AnchorMailbox contains the pattern of ServerInfo~*/*
    -------------------------------------------------------------------]=])
    hunt.log(out)
end

hunt.log("CVE-2021-26858: Grabbing relevant Exchange log files via Powershell")
out, err = hunt.env.run_powershell([[findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"]])
if err then 
    hunt.error(err)
else 
    hunt.log([=[-- If activity is detected, the logs specific to the application specified in the AnchorMailbox path can be used to help determine what actions were taken.
    -- These logs are located in the %PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging directory.

    -- CVE-2021-26858 exploitation can be detected via the Exchange log files:
    -- C:\Program Files\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog
    -- Files should only be downloaded to the %PROGRAMFILES%\Microsoft\Exchange Server\V15\ClientAccess\OAB\Temp directory
    -- In case of exploitation, files are downloaded to other directories (UNC or local paths)
    -------------------------------------------------------------------]=])
    hunt.log(out)
end

    
hunt.log("CVE-2021-26857: Grabbing relevant Windows Application event logs via Powershell")
out, err = hunt.env.run_powershell([[Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }]])
if err then 
    hunt.error(err)
else 
    hunt.log([=[-- CVE-2021-26857 exploitation can be detected via the Windows Application event logs
    -- Exploitation of this deserialization bug will create Application events with the following properties:
    -- Source: MSExchange Unified Messaging
    -- EntryType: Error
    -- Event Message Contains: System.InvalidCastException
    -------------------------------------------------------------------]=])
    hunt.log(out)
end


hunt.log([=[CVE-2021-27065: Grabbing relevant logs (V15\Logging\ECP\Server) via Powershell]=])
out, err = hunt.env.run_powershell([[Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory']])
if err then 
    hunt.error(err)
else 
    hunt.log([=[-- CVE-2021-27065 exploitation can be detected via the following Exchange log files:
    -- C:\Program Files\Microsoft\Exchange Server\V15\Logging\ECP\Server
    -- All Set-<AppName>VirtualDirectory properties should never contain script. InternalUrl and ExternalUrl should only be valid Uris.
    -------------------------------------------------------------------]=])
    hunt.log(out)
end


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

hunt.log(f"Yara scan completed. Result=${result}. Added ${n} paths (all bad and suspicious matches) to Artifacts for processing and retrieval.")
