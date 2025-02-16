<h1>Creating a Basic Home Security Operations Center (SOC)</h1>

 

**Objective**: Set Up a Basic Home SOC in Azure from scratch. Create a Virtual Machine (VM) and open it to the Internet as a Honeypot. Forward Logs to a Central Repository. Integrate Microsoft Sentinel to analyze real-world attack data.  
 <br/>


<h2>🛠 Step 1: Create the Honeypot (Azure Virtual Machine) </h2>  
  
🖥 [Azure](https://portal.azure.com)       
  
   - Create a new **Windows 10 Virtual Machine** (Choose an apporiate size).    
   - Go to the **Network Security Group** for your virtual machine and create a rule that allows all traffic innbound.  
   - Log into your **Virtual Machine** and turn off the **Windows Firewall** `start > wf.msc > properties > all off`.    
    
  
 <br/>    

  
<h2>🛠 Step 2: Logging into the VM and Inspecting Logs </h2>  

  - Fail 3 Logins as **"Employee"** (or some other Username).
  - Login to your **Virtual Machine**.
  - Open up **Event Viewer** and Inspect the **Security Logs**.
  - See the 3 failed logins as **"Employee"**, **Event ID 4625**

  ✅ **Next, We are going to create a Central Log Repository called LAW.**  
  
 </br>    
    
              
<h2>🛠 Step 3: Log Fowarding and KQL </h2>    
    
  -  Create **Log Analytics Workspace (LAW)**.   
  -  Create a **Sentinel Instance** and connect it to **Log Analytics**.    
  -  (Observe Architecture)
  -  Configure the **Windows Security Events via AMA** connector.  
  -  Query for Logs within the **LAW**.  

  ✅ **We can now query the Log Analytics Workspace as well as the SIEM.**  
  
     
   
  📌 Observe **Virtual Machine** Logs  

       SecurityEvent
       | where EventId == 4625
 
  ✅ (Observe Architecture)  
  </br>  
  

  
<h2>🛠 Step 4: Log Enrichment and Finding Location Data </h2>       

  - Observe the **Security Events** Logs in the **Logs Analytics Workspace**
  - Use the **IP Address** to derive the location data.
  - Import this [Spreadsheet](https://drive.google.com/file/d/13EfjM_4BohrmaxqXZLB5VUBIz2sv9Siz/view?usp=sharing) as a **"Sentinel Watchlist"**.
  
📌 **Create the "Sentinel Watchlist"**    

   **Name/Alias: geoip**  
   **Source Type: Local File**  
   **Number of Lines before Row: 0**  
   **Search Key: Network**  

 ✅ (Observe Architecture)  
   

📌 **Observe the Logs to see where the attacks are coming from.**   

      let GeoIPDB_FULL = _GetWatchlist("geoip");
      let WindowsEvents = SecurityEvent
          | where IpAddress == <attacker IP address>
          | where EventID == 4625
          | order by TimeGenerated desc
          | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
      WindowsEvents  
        
  ✅ (Observe Architecture)   
  
  
      
<h2>🛠 Step 5: Attack Map Creation </h2>   

  🔹 Create a new Workbook within Sentinel.  
  
   - Delete the Prepopulated Elements and add a "Query" Element.
   - Go to the **Advanced Editor** tab.
   - Copy & Paste **JSON**:

         {
                 "type": 3,
                 "content": {
                	"version": "KqlItem/1.0",
                 "query": "let GeoIPDB_FULL = _GetWatchlist(\"geoip\");\nlet WindowsEvents =
         SecurityEvent;\nWindowsEvents | where EventID == 4625\n| order by TimeGenerated desc\n|
         evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network)\n| summarize FailureCount = count() by
         IpAddress, latitude, longitude, cityname, countryname\n| project FailureCount, AttackerIp =
         IpAddress, latitude, longitude, city = cityname, country = countryname,\nfriendly_location =
         strcat(cityname, \" (\", countryname, \")\");",
                	"size": 3,
                	"timeContext": {
		                       "durationMs": 2592000000
                	},
                	"queryType": 0,
                	"resourceType": "microsoft.operationalinsights/workspaces",
                	"visualization": "map",
                	"mapSettings": {
                       		"locInfo": "LatLong",
                       		"locInfoColumn": "countryname",
                       		"latitude": "latitude",
                       		"longitude": "longitude",
                       		"sizeSettings": "FailureCount",
                       		"sizeAggregation": "Sum",
                       		"opacity": 0.8,
                       		"labelSettings": "friendly_location",
                       		"legendMetric": "FailureCount",
                       		"legendAggregation": "Sum",
                       		"itemColorSettings": {
                       		"nodeColorField": "FailureCount",
                       		"colorAggregation": "Sum",
                       		"type": "heatmap",
                       		"heatmapPalette": "greenRed"
                       		}
	                }
	                },
	                "name": "query - 0"
         }  
      
    
         
📌 **Observe the query**    
📌 **Observe the map settings**    
📌 **Observe the map**  

  

  


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
