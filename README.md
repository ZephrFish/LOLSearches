# LOLSearches
This repository complements my [Adversarial Sysadmin](https://blog.zsec.uk/lolsysadmin/) blog post and contains additional search queries and operators that will help you find sensitive data in SharePoint and Windows Explorer.

## SharePoint KQL Queries

### Finding Credentials within Files
```
content:"password" OR content:"username" OR content:"credential" OR content:"secret" OR content:"key" OR content:"token" OR content:"login"
```

### Scripts Containing Sensitive Information
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:sh OR FileExtension:cmd OR FileExtension:py) AND (content:"password" OR content:"secret" OR content:"key" OR content:"credential" OR content:"token")
```

### Files Containing the Domain “ACME"
```
content:"ACME\\"
```

### Files Containing Sysadmin Commands
```
content:"net use" OR content:"ipconfig" OR content:"netstat" OR content:"ping" OR content:"tracert" OR content:"nslookup" OR content:"net user" OR content:"net localgroup"
```

### Comprehensive Search for Scripts with Credential Patterns
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:sh OR FileExtension:cmd OR FileExtension:py OR FileExtension:js OR FileExtension:ts OR FileExtension:rb OR FileExtension:pl OR FileExtension:php OR FileExtension:cs OR FileExtension:java OR FileExtension:go OR FileExtension:r OR FileExtension:sql OR FileExtension:groovy OR FileExtension:scala OR FileExtension:kt OR FileExtension:vb OR FileExtension:vbs OR FileExtension:psm1 OR FileExtension:jsx OR FileExtension:TSX) AND
(content:"password=" OR content:"password :" OR content:"password =>" OR content:"passwd=" OR content:"passwd :" OR content:"passwd =>" OR content:"pwd=" OR content:"pwd :" OR content:"pwd =>" OR content:"secret=" OR content:"secret :" OR content:"secret =>" OR content:"key=" OR content:"key :" OR content:"key =>" OR content:"api_key" OR content:"apiKey" OR content:"token=" OR content:"token :" OR content:"token =>" OR content:"access_token" OR content:"client_secret" OR content:"private_key" OR content:"BEGIN PRIVATE KEY" OR content:"aws_access_key_id" OR content:"aws_secret_access_key")
```

### Advanced Search with Wildcards and Proximity
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:sh OR FileExtension:cmd OR FileExtension:py OR FileExtension:js OR FileExtension:ts OR FileExtension:rb OR FileExtension:pl OR FileExtension:php OR FileExtension:cs OR FileExtension:java OR FileExtension:go OR FileExtension:r OR FileExtension:sql OR FileExtension:groovy OR FileExtension:scala OR FileExtension:kt OR FileExtension:vb OR FileExtension:vbs OR FileExtension:psm1 OR FileExtension:jsx OR FileExtension:tsx) AND ((content:"password*"~5) OR (content:"passwd*"~5) OR (content:"pwd*"~5) OR (content:"secret*"~5) OR (content:"key*"~5) OR (content:"token*"~5) OR (content:"api_key*"~5) OR (content:"apiKey*"~5) OR (content:"access_token*"~5) OR (content:"client_secret*"~5) OR (content:"private_key*"~5) OR (content:"aws_access_key_id*"~5) OR (content:"aws_secret_access_key*"~5))
```

### Regular Expression Search for Credential Patterns
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:sh OR FileExtension:cmd OR FileExtension:py OR FileExtension:js OR FileExtension:ts OR FileExtension:rb OR FileExtension:pl OR FileExtension:php OR FileExtension:cs OR FileExtension:java OR FileExtension:go OR FileExtension:r OR FileExtension:sql OR FileExtension:groovy OR FileExtension:scala OR FileExtension:kt OR FileExtension:vb OR FileExtension:vbs OR FileExtension:psm1 OR FileExtension:jsx OR FileExtension:tsx) AND content:/.*(password|passwd|pwd|secret|key|token|api_key|apiKey).*(=|:|=>).*/
```

### Searching for Encoded or Obfuscated Credentials (I've found this to be a bit hit or miss)
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:sh OR FileExtension:cmd OR FileExtension:py OR FileExtension:js OR FileExtension:ts OR FileExtension:rb OR FileExtension:pl OR FileExtension:php OR FileExtension:cs OR FileExtension:java OR FileExtension:go OR FileExtension:r OR FileExtension:sql OR FileExtension:groovy OR FileExtension:scala OR FileExtension:kt OR FileExtension:vb OR FileExtension:vbs OR FileExtension:psm1 OR FileExtension:jsx OR FileExtension:tsx) AND (content:"Base64.decode" OR content:"FromBase64String" OR content:"Convert.FromBase64String" OR content:"atob(" OR content:"btoa(" OR content:"decode64" OR content:"encode64")
```

### Including Domain-Specific Patterns
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:sh OR FileExtension:cmd OR FileExtension:py OR FileExtension:js OR FileExtension:ts OR FileExtension:rb OR FileExtension:pl OR FileExtension:php OR FileExtension:cs OR FileExtension:java OR FileExtension:go OR FileExtension:r OR FileExtension:sql OR FileExtension:groovy OR FileExtension:scala OR FileExtension:kt OR FileExtension:vb OR FileExtension:vbs OR FileExtension:psm1 OR FileExtension:jsx OR FileExtension:tsx) AND content:"ACME\\" AND (content:"password" OR content:"secret" OR content:"token")
```

### Comprehensive Query Combining Multiple Patterns
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:sh OR FileExtension:cmd OR FileExtension:py OR FileExtension:js OR FileExtension:ts OR FileExtension:rb OR FileExtension:pl OR FileExtension:php OR FileExtension:cs OR FileExtension:java OR FileExtension:go OR FileExtension:r OR FileExtension:sql OR FileExtension:groovy OR FileExtension:scala OR FileExtension:kt OR FileExtension:vb OR FileExtension:vbs OR FileExtension:psm1 OR FileExtension:jsx OR FileExtension:tsx) AND ((content:/.*(password|passwd|pwd|secret|key|token|api_key|apiKey).*(=|:|=>).*/) OR (content:"BEGIN PRIVATE KEY" OR content:"END PRIVATE KEY") OR (content:"aws_access_key_id" OR content:"aws_secret_access_key") OR (content:"Base64.decode" OR content:"FromBase64String" OR content:"Convert.FromBase64String" OR content:"atob(" OR content:"btoa(" OR content:"decode64" OR content:"encode64") OR content:"ACME\\")
```

### Searching for User and Password Pairings
```
(FileExtension:ps1 OR FileExtension:py OR FileExtension:js OR FileExtension:java OR FileExtension:cs OR FileExtension:php OR FileExtension:rb OR FileExtension:go OR FileExtension:kt) AND (content:/.*(username|user|login).*(=|:|=>).*/ AND content:/.*(password|passwd|pwd|secret).*(=|:|=>).*/)
```

### Searching for Cloud Service Credentials
```
(FileExtension:json OR FileExtension:yaml OR FileExtension:yml OR FileExtension:xml OR FileExtension:properties OR FileExtension:env OR FileExtension:ini) AND (content:"aws_access_key_id" OR content:"aws_secret_access_key" OR content:"azure_subscription_id" OR content:"azure_tenant_id" OR content:"azure_client_id" OR content:"azure_client_secret" OR content:"gcp_project_id" OR content:"gcp_client_id" OR content:"gcp_client_secret")
```

### Credentials in Comments
```
(FileExtension:ps1 OR FileExtension:py OR FileExtension:js OR FileExtension:java OR FileExtension:cs OR FileExtension:php OR FileExtension:rb OR FileExtension:go OR FileExtension:kt) AND content:/.*(\/\/|#|\/\*|\*).*(password|secret|token).*/
```

### Searching for Hard-Coded URLs with Credentials
```
(FileExtension:ps1 OR FileExtension:py OR FileExtension:js OR FileExtension:java OR FileExtension:cs OR FileExtension:php OR FileExtension:rb OR FileExtension:go OR FileExtension:kt OR FileExtension:sh OR FileExtension:cmd) AND content:/.*(http|https|ftp):\/\/.*(username|user|login|password|passwd|pwd|token).*/
```

### Combining with Sysadmin Commands
```
(FileExtension:ps1 OR FileExtension:bat OR FileExtension:cmd OR FileExtension:sh) AND (content:"net use" OR content:"ipconfig" OR content:"netstat" OR content:"ping" OR content:"tracert" OR content:"nslookup" OR content:"net user" OR content:"net localgroup") AND (content:/.*(password|passwd|pwd|secret|key|token|api_key|apiKey).*(=|:|=>).*/)
```

## Windows Explorer Searches
### Searching for Files Containing “password”
```
content:"password"
```

### Searching for Files Containing “ACME"
```
content:"ACME\"
```

### Searching for Multiple Keywords (OR Logic)
```
content:"password" OR content:"secret" OR content:"token"
```

### Combining Content and File Type Searches
```
(ext:.ps1 OR ext:.bat OR ext:.cmd OR ext:.vbs) (content:"password" OR content:"secret")
```

### Creds in Scripts
```
(ext:.ps1 OR ext:.bat OR ext:.cmd OR ext:.py OR ext:.js OR ext:.php OR ext:.java) (content:"password" OR content:"passwd" OR content:"secret" OR content:"token" OR content:"apiKey")
```

### Date Range Searches
```
datecreated:01/01/2023..31/12/2025 (ext:.ps1 OR ext:.bat OR ext:.cmd OR ext:.py OR ext:.js OR ext:.php OR ext:.rb OR ext:.pl OR ext:.java OR ext:.cs) content:"password"
```



