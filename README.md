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
    
  -  Create **Log Analytics Workspace**.   
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
  
Now that we've assessed gaps, create an **action plan** to meet **ISO 27001** requirements.  
</br>  

      
  🔹 Compliance Readiness Plan    
| **ISO 27001 Requirement** | **Current Status** | **Action Required** | **Owner** | **Due Date** | 
| ------------------------- | ------------------ | ------------------- | --------- | ------------ | 
| Security Policies | Not documented | Create & implement policies | IT Team | 1 Week | 
| Access Control | Extra admin accounts found | Remove unneccessary accounts | Security Team | ASAP | 
| Logging & Monitoring | Logs not reviewed | Set up log monitoring with SIEM | IT security | 2 Weeks | 
| Data Encryption | No encryption for sensitive data | Implement disk & data encryption | Compliance Team | 2 Weeks | 
| Incident Response Plan | Not defined | Develop and document an IR plan | IT Security | 1 Week |  

✅ **This table helps track compliance progress!**  


    
<h2>🛠 Step 4: Implement Compliance Fixes <br/>  
   
🔹 Fix Security Gaps to Pass an Audit </h2>  
  
  🖥 **Windows Compliance Fixes**   

  📌 **Enable BitLocker** for **Data Encryption**  

        Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnly  

  ✅ **Ensures sensitive data is encrypted.**  

  📌 **Restrict Admin Accounts **
  
        Remove-LocalUser -Name "OldAdmin"  

  ✅ **Reduce Attack Surface**  

  📌 **Enable Windows Event Logging**  

        auditpol /get /category:*  
        
  ✅ **Ensures security incidents are logged.**  
  </br>  

        
  <h2>🐧 Linux Compliance Fixes </h2>  
  
  📌 **Enable Disk Encryption with LUKS**  

         sudo cryptsetup luksFormat /dev/sdb  
         
✅ **Encrypts sensitive data.**  
  
  📌 **Implement SSH Key-Based Authentication**

        sudo nano /etc/ssh/sshd_config
        # Set:
        PasswordAuthentication no
        PermitRootLogin no  


         sudo systemctl restart ssh  
         
 ✅ **Prevents brute-force attacks.**  
   
 📌 **Enable Automatic Security Updates**  

        sudo apt install unattended-upgrades
        sudo dpkg-reconfigure unattended-upgrades  
  
  ✅ **Ensures critical patches are always applied**  
  </br>  

    
<h2>🛠 Step 5: Conduct a Mock Audit & Review Findings </h2>    
     
<h3>🔹 Step 5.1: Perform a Compliance Check  </h3>  

 Run security scans again to confirm fixes.     

  ✅ **Windows Compliance Check**  

        Get-BitLockerVolume
        Get-EventLog -LogName Security -Newest 10  
          
  ✅ **Linux Compliance Check**       

       sudo lynis audit system  
  
  ✅ **Check User Access Logs**  

      sudo lastlog  

  📌 **Create a final audit report summarizing compliance progress.**  
 </br> 
  
<h2> 📄 Sample Audit Readiness Report </h2>  

**ISO 27001 Readiness Assessment Report**  
**Date:** \[2/16/2025]  
**Scope:** Home Lab Security Compliance   

<h3> 🔹 Summary of Compliance Status </h3>  
  
| Control Area | Audit Result | Status | 
| ------------ | ------------ | ------ | 
| Security Policies | Policies implemented | ✅ Passed | 
| Access Control | Extra admin accounts removed | ✅ Passed | 
| Logging & Monitoring | Logs centralized in SIEM | ✅ Passed | 
| Data Encryption | BitLocker & LUKS enabled | ✅ Passed | 
| Incident Response Plan | IR plan documented & tested | ✅ Passed |  
  
<h3> 🔹 Remaining Action Items </h3>  

📌 **Conduct periodic compliance reviews**    
📌 **Automate audit checks with Powershell or Bash scripts**    
📌 **Test Incident Response scenarios quarterly**  
  
✅ **Final Recommendation: Ready for an External Audit!**  

  

  


<!--
 ```diff
- text in red
+ text in green
! text in orange
# text in gray
@@ text in purple (and bold)@@
```
--!>
