--[=[ 
name: Lnk Parser
filetype: Infocyte Extension
type: Collection
description: Parses .lnk files and adds their target binary to Artifacts
author: Infocyte
guid: 7d8a4d8e-fda2-46ca-945b-dae37e4a6100
created: 2020-12-03
updated: 2020-12-03

# Global variables
globals:
  - name: trailing_days
    description: Number of days to go back in the logs
    type: number
    default: 90
    required: false

# Runtime arguments
args:

]=]


--[=[ SECTION 1: Inputs ]=]
-- hunt.arg(name = <string>, isRequired = <boolean>, [default])
-- hunt.global(name = <string>, isRequired = <boolean>, [default])

trailing_days = hunt.global.number("trailing_days", false, 90)

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
        hunt.debug(msg)
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

function path_exists(path)
    --[=[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]=] 

   ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

--[=[ SECTION 3: Collection ]=]

host_info = hunt.env.host_info()
hunt.debug(f"Starting Extention. Hostname: ${host_info:hostname()} [${host_info:domain()}], OS: ${host_info:os()}")
script = f"$trailing_days=${trailing_days}\n"
script = script..[=[
Function Parse-LnkFile {
    param (
        [parameter(Mandatory=$true,Position=1,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)] 
        [Alias("FullName")]
        [string]$Path
    )
    BEGIN { 
        $sh = New-Object -ComObject WScript.Shell
    }
    PROCESS { 
        $Path = Resolve-Path $Path
        if (Test-Path $Path) {
            $target = $sh.CreateShortcut($Path).TargetPath
            if ($target -AND -NOT (Test-Path $target -PathType Container)) {
                "$Path, $target"  
            }        
        } 
    }
}
function Get-LnkFiles ([switch]$Parse, [int]$TrailingDays = 90) {
    $startdate = (Get-date -hour 0 -minute 0 -second 0).AddDays(-$TrailingDays)
    $linkfiles = @()
    $RecentFilesFolder = "AppData/Roaming/Microsoft/Windows/Recent/"
    $userfolders = "C:/Users/"
    $users = Get-ChildItem $userfolders -ea 0 | where { $_.name -ne "Public" } | select name -ExpandProperty name    
    $users | % {
        $linkfiles += Get-ChildItem -File -Recurse -Path "$userfolders/$_" -Filter *.lnk -depth 1 -ea 0 | where { $_.LastWriteTimeUtc -gt $startdate }
        $linkfiles += Get-ChildItem -File -Recurse -Path "$userfolders/$_/AppData/Roaming/Microsoft/Windows/Recent" -Filter *.lnk -ea 0 | where { $_.LastWriteTimeUtc -gt $startdate }
        $linkfiles += Get-ChildItem -File -Path "c:/programdata/microsoft/windows/start menu/programs/startup" -Filter *.lnk -ea 0 | where { $_.LastWriteTimeUtc -gt $startdate }
    }

    Try {
        if ($parse) {
            $linkfiles | sort lastwritetime | Parse-LnkFile
        } else {
            $linkfiles | sort lastwritetime
        }
    } catch {}
}

$out = Get-LnkFiles -TrailingDays $trailing_days -Parse
Return $out
]=]

hunt.debug(f"Running powershell script:\n${script}")
out, err = hunt.env.run_powershell(script)
if not out then 
    hunt.error(err)
    return
end
hunt.verbose(out)

paths = {}
links = {} -- add to keys of list to easily unique paths
for l in string.gmatch(out, "[^\r\n]+") do -- parse by line
    -- Create Link
    n = false
    link = {}
    for p in string.gmatch(l, "[^,]+") do -- parse by comma
        path = string.gsub(p, "%s+", "") -- strip whitespace
        if not n then
            link["Path"] = path
            n = true
        else
            link["Target"] = path
            n = false
        end
    end

    if not paths[link['Target']] and path_exists(link["Target"]) then
        if is_executable(link["Target"]) then
            -- Add link if file exists and is an executable
            hunt.log(f"LINK[${link['Path']}] = ${link['Target']}")
            table.insert(links, link)
            paths[link['Target']] = true
        end
    elseif not paths[link['Target']] then
        -- Add link if file does not exists
        hunt.log(f"LINK[${link['Path']}] = ${link['Target']}")
        table.insert(links, link)
        paths[link['Target']] = true
    end
end

-- Add targets to Autostarts list for analysis
n = 0
for _,link in pairs(links) do
    print("Adding file: "..link['Target'])
	-- Create a new artifact
    autostart = hunt.survey.autostart()	
    autostart:type("Lnk")
    autostart:exe(link['Target'])
    -- autostart:params()
    autostart:location(link['Path'])
    hunt.survey.add(autostart)
    n = n + 1
end

-- Set threat status
hunt.status.good()
hunt.log(f"Lnk file parsing completed. Added ${n} paths to Artifacts for processing and retrieval.")