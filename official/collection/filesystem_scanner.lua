--[[
    Infocyte Extension
    Name: Filesystem Scanner
    Type: Collection
    Description: | Scans system for files matching a set of regexes against filenames|
    Author: Chris Gerritz
    Guid: 1775f23f-34a6-4f83-91e6-49c48faa66bb
    Created: 20200406
    Updated: 20200514
--]]


--[[ SECTION 1: Inputs --]]
searchpaths = {
    'C:\\Users\\',
    'C:\\Windows\\Temp'
}

--Search Options:
startdate = '05-01-2020'
recurse_depth = 3

filename_regex_suspicious = {
    [[^.*\.txt$]]
}

filename_regex_bad = {
    [[^[0-9,A-Z,a-z]{4,6}-Readme\.txt$]],
}


--[[ SECTION 2: Functions --]]

powershell = {}
function powershell.run_command(command)
    --[[
        Input:  [String] Small Powershell Command
        Output: [Bool] Success
                [String] Output
    ]]
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not command or (type(command) ~= "string") then 
        throw "Required input [String]command not provided."
    end

    print("[PS] Initiatializing Powershell to run Command: "..command)
    cmd = ('powershell.exe -nologo -nop -command "& {'..command..'}"')
    pipe = io.popen(cmd, "r")
    output = pipe:read("*a") -- string output
    ret = pipe:close() -- success bool
    return ret, output
end

function powershell.run_script(psscript)
    --[[
        Input:  [String] Powershell script. Ideally wrapped between [==[ ]==] to avoid possible escape characters.
        Output: [Bool] Success
                [String] Output
    ]]
    debug = debug or true
    if not hunt.env.has_powershell() then
        throw "Powershell not found."
    end

    if not psscript or (type(psscript) ~= "string") then 
        throw "Required input [String]script not provided."
    end

    os.execute("mkdir "..os.getenv("systemroot").."\\temp\\ic")
    print("Initiatializing Powershell to run Script")

    local tempfile = os.getenv("systemroot").."\\temp\\ic"..os.tmpname().."script.ps1"
    local f = io.open(tempfile, 'w')
    script = "# Ran via Infocyte Powershell Extension\n"..psscript
    f:write(script) -- Write script to file
    f:close()

    -- Feed script to Invoke-Expression to execute
    -- This method bypasses translation issues with popen's cmd -> powershell -> cmd -> lua shinanigans
    local cmd = 'powershell.exe -nologo -nop -command "gc '..tempfile..' | Out-String | iex'
    print("Executing: "..cmd)
    local pipe = io.popen(cmd, "r")
    local output = pipe:read("*a") -- string output
    if debug then 
        for line in string.gmatch(output,'[^\n]+') do
            if line ~= '' then print("[PS]: "..line) end
        end
    end
    local ret = pipe:close() -- success bool
    os.remove(tempfile)
    if ret and string.match( output, 'FullyQualifiedErrorId' ) then
        ret = false
    end
    return ret, output
end

-- FileSystem Functions --
function path_exists(path)
    --[[
        Check if a file or directory exists in this path. 
        Input:  [string]path -- Add '/' on end of the path to test if it is a folder
        Output: [bool] Exists
                [string] Error message -- only if failed
    ]] 
   local ok, err = os.rename(path, path)
   if not ok then
      if err == 13 then
         -- Permission denied, but it exists
         return true
      end
   end
   return ok, err
end

function get_filename(path)
    match = path:match("^.+[\\/](.+)$")
    return match
end
  
function get_fileextension(path)
    match = path:match("^.+(%..+)$")
    return match
end

function userfolders()
    --[[
        Returns a list of userfolders to iterate through
        Output: [list]ret -- List of userfolders (_, path)
    ]]
    local paths = {}
    local u = {}
    for _, userfolder in pairs(hunt.fs.ls("C:\\Users", {"dirs"})) do
        if (userfolder:full()):match("Users") then
            if not u[userfolder:full()] then
                -- filter out links like "Default User" and "All Users"
                u[userfolder:full()] = true
                table.insert(paths, userfolder:path())
            end
        end
    end
    return paths
end


function parse_csv(path, sep)
    --[[
        Parses a CSV on disk into a lua list.
        Input:  [string]path -- Path to csv on disk
                [string]sep -- CSV seperator to use. defaults to ','
        Output: [list]
    ]] 
    tonum = true
    sep = sep or ','
    local csvFile = {}
    local file,msg = io.open(path, "r")
    if not file then
        hunt.error("CSV Parser failed: ".. msg)
        return nil
    end
    local header = {}
    for line in file:lines() do
        local n = 1
        local fields = {}
        if not line:match("^#TYPE") then 
            for str in string.gmatch(line, "([^"..sep.."]+)") do
                s = str:gsub('"(.+)"', "%1")
                if not s then 
                    hunt.debug(line)
                    hunt.debug('column: '..v)
                end
                if #header == 0 then
                    fields[n] = s
                else
                    v = header[n]
                    fields[v] = tonumber(s) or s
                end
                n = n + 1
            end
            if #header == 0 then
                header = fields
            else
                table.insert(csvFile, fields)
            end
        end
    end
    file:close()
    return csvFile
end


--[[ SECTION 3: Collection --]]


-- All Lua and hunt.* functions are cross-platform.
host_info = hunt.env.host_info()
hunt.verbose("Starting Extention. Hostname: " .. host_info:hostname() .. ", OS: " .. host_info:os() .. ", Architecture: " .. host_info:arch())
hunt.status.good()

tmp = "C:\\windows\\temp\\ic\\out.csv"
for _, path in pairs(searchpaths) do 
    for _,m in pairs(filename_regex_suspicious) do 
        cmd = "Get-ChildItem -Path '"..path.."' -Recurse -Depth "..recurse_depth.." -Filter *.txt | where-object { $_.CreationTimeUtc -gt [DateTime]'"..startdate.."' -AND $_.Name -match '"..m.."' } | select FullName, CreationTimeUtc, LastWriteTimeUtc | Sort-Object creationTimeUtc -Descending| Export-CSV "..tmp.." -Force -Delimiter ';' -NoTypeInformation; return $true"
        print(cmd)
        success, results = powershell.run_script(cmd)
        if success and path_exists(tmp) then 
            csv = parse_csv("C:\\windows\\temp\\ic\\out.csv", ";")
            for _,file in pairs(csv) do
                hunt.status.suspicious() -- Set Threat to Suspicious on finding
                hunt.log("Suspicious ["..file['CreationTimeUtc'].."]: "..file['FullName']) -- Send to Infocyte Extension Output
            end
        end
    end
    os.remove(tmp)
    for _,m in pairs(filename_regex_bad) do 
        cmd = "Get-ChildItem -Path '"..path.."' -Recurse -Depth "..recurse_depth.." -Filter *.txt | where-object { $_.CreationTimeUtc -gt [DateTime]'"..startdate.."' -AND $_.Name -match '"..m.."' } | select FullName, CreationTimeUtc, LastWriteTimeUtc | Sort-Object creationTimeUtc -Descending | Export-CSV "..tmp.." -Force -Delimiter ';' -NoTypeInformation; return $true"
        print(cmd)
        success, results = powershell.run_script(cmd)
        if success and path_exists(tmp) then 
            csv = parse_csv("C:\\windows\\temp\\ic\\out.csv", ";")
            for _,file in pairs(csv) do
                hunt.status.suspicious() -- Set Threat to Suspicious on finding
                hunt.log("Suspicious ["..file['CreationTimeUtc'].."]: "..file['FullName']) -- Send to Infocyte Extension Output
            end
        end
    end
end
os.remove(tmp)

hunt.log("Result: Extension successfully executed")