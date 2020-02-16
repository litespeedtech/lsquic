$set_found = $false
$file_list = @()
Get-Content CMakeLists.txt | %{
    if($_ -match "^SET\(TESTS$") {
        $set_found = $true
    }
    elseif ($set_found){
        if($_ -match "\)") { write-host $file_list; exit}
        $file_list += "test_" + $_.Trim()
    }
}
