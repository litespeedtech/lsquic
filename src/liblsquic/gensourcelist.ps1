$set_found = $false
$file_list = @()
Get-Content CMakeLists.txt | %{
    if($_ -match "^SET\(lsquic_STAT_SRCS$") {
        $set_found = $true
    }
    elseif ($set_found){
        if($_ -match "\)") { write-host $file_list; exit}
		if( test-path $_.Trim())
		{
		  $file_list += $_.Trim()
		}
    }
}
