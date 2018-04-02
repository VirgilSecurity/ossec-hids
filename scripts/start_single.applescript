tell application "Finder"
	set current_path to container of (path to me) as alias
end tell

tell application "Terminal"
	set p to POSIX path of current_path
	set cd_ossec_path to "cd " & p & "/.. && "
	
	
	do script cd_ossec_path & "docker-compose down && docker-compose pull && docker-compose up -d ossec-server ossec-client-1"
	activate
	
	set current settings of selected tab of front window to settings set "Homebrew"
	
	repeat until front window is not busy
		delay 1
	end repeat
	
	my makeTab()
	do script cd_ossec_path & "docker-compose logs -f ossec-server" in front window
	
	my makeTab()
	do script cd_ossec_path & "docker-compose logs -f ossec-client-1" in front window
	
end tell

on makeTab()
	tell application "System Events" to keystroke "t" using {command down}
	delay 0.2
end makeTab