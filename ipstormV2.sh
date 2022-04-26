#!/bin/bash
idate=$(date)
figlet -t -k -f /usr/share/figlet/future.tlf "IP-Storm"

rm -rf Filtered_Sorted_IPdump IP_Abuseip_Stats.csv Virustotal_Stats.csv
echo "[!] Enter the name of wireshark file"
read wfile

echo -e "\n[+] Fetching source IPs"
tshark -nr $wfile -T fields -e ip.src > ipdump

echo -e "\n[+] Fetching destination IPs"
tshark -nr $wfile -T fields -e ip.dst >> ipdump

echo -e "\n[+] Removing blank lines"
sed -i '/^$/d' ipdump

echo -e "\n[+] Finalizing"
cat ipdump | cut -d "," -f1 > FilteredSortedIPdump

echo -e "\n[+] Sorting and removing duplicate IPs"
cat FilteredSortedIPdump | sort | uniq > Filtered_Sorted_IPdump
cat "end" >> Filtered_Sorted_IPdump

rm -rf ipdump FilteredSortedIPdump

rm -rf IP_Virustotal_Stats
rm -rf temp.json temp2.json


#=========AbuseIP
rm -rf IP_Abuseip_Stats
ipcount=0

Aapikey=("916a56cee1091ad2d02129038af6bf8b4c59e3323a3f8285d78fc4864dd62a7a292f91c3043995b6" 
         "740e95aa8ac256d38c28fd09a1792b2a95f9368c800417f5fc61025488ba824c9a72830e998277e1" 
         "Db5bc08aac52577237e6bdc9c16a7f317e0ad527d00cd10cc157503490384c45e2e23e959b9d8e00" 
         "726f3d271fcbb94041046622d40f91f4ad72c49512be32e5eb04504b4774dce195a9c249064ded58" 
         "5351bc3edb061f3d788ac1b86f0132e678d876a0ce2b8126aaae88db109ed8965a2630b79df4202a") 
Acount=0

echo -e "IP_Address","AbuseIPScore","VirustotalScore","VirustotalAgents","CountryCode","CountryName","ISP","Domain","IsPublic","IPversion","IsWhitelisted","UsageType","Hostnames","TotalReports","NumberOfDistictUsers","LastReportedAt","ReportedAt","Categories","ReportedID","ReporterCountryCode","ReporterCountryName\n"  >> IP_Abuseip_Stats.csv
while read line; do
    ipcount=$(( ipcount+1 ))
    Vfinal=()
    echo "[A$ipcount] --------------------------------"$line"--------------------------------------"
    curl -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=$line"   -d maxAgeInDays=90   -d verbose   -H "Key: ${Aapikey[$Acount]}"   -H "Accept: application/json" > temp.json
    s=$(jq '.data.abuseConfidenceScore' temp.json)
    echo $s
    if ! [[ "$s" =~ ^[0-9]+$ ]] #TRY AGAIN ONCE
    then
    echo -e "\nRetrying\n"
    curl -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=$line"   -d maxAgeInDays=90   -d verbose   -H "Key: ${Aapikey[$Acount]}"   -H "Accept: application/json" > temp.json
    s=$(jq '.data.abuseConfidenceScore' temp.json)
    echo $s
    fi
    if ! [[ "$s" =~ ^[0-9]+$ ]]
    then
           #Acount=$(( Acount+1 ))
           s=$(curl -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=$line"   -d maxAgeInDays=90   -d verbose   -H "Key: ${Aapikey[$Acount]}"   -H "Accept: application/json" | jq -r '.data.abuseConfidenceScore' temp.json)
	   if ! [[ "$s" =~ ^[0-9]+$ ]] #checking if another key is also not giving null value. Otherwise using another key
           then
                Acount=$(( Acount+1 ))
                s=$(curl -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=$line"   -d maxAgeInDays=90   -d verbose   -H "Key: ${Aapikey[$Acount]}"   -H "Accept: application/json" | jq -r '.data.abuseConfidenceScore' temp.json) 


		if ! [[ "$s" =~ ^[0-9]+$ ]] #checking if another key is also not giving null value. Otherwise using another key
                then
                        Acount=$(( Acount+1 ))
                        s=$(curl -G https://api.abuseipdb.com/api/v2/check   --data-urlencode "ipAddress=$line"   -d maxAgeInDays=90   -d verbose   -H "Key: ${Aapikey[$Acount]}"   -H "Accept: application/json" | jq -r '.data.abuseConfidenceScore' temp.json)

                fi
           fi
    fi
#=========================================================================== IF ONE KEY FAILS THEN OTHER KEY WILL BE USED
#REMOVE FOR LOOP

echo -e "\n\n"

if  [[ "$s" != "null" ]]     
then
	ip=$(jq -r '.data."ipAddress"  | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	ip="${ip//,/}"
		    
	ispub=$(jq -r '.data."isPublic"' temp.json 2> /dev/null)        
	 ispub="${ispub//,/}"
		    
	ipv=$(jq -r '.data."ipVersion"' temp.json 2> /dev/null)        
	ipv="${ipv//,/}"
		    
	iswhi=$(jq -r '.data."isWhitelisted"' temp.json 2> /dev/null)        
	iswhi="${iswhi//,/}"
		    
	score=$(jq -r '.data."abuseConfidenceScore"' temp.json 2> /dev/null)        
	score="${score//,/}"
		    
	cc=$(jq -r '.data."countryCode" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	cc="${cc//,/}"
		    
	cn=$(jq -r '.data."countryName" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	n="${cn//,/}"
		    
	ut=$(jq -r '.data."usageType" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	ut="${ut//,/}"
		    
	isp=$(jq -r '.data."isp" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	isp="${isp//,/}"
		    
	domain=$(jq -r '.data."domain" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	domain="${domain//,/}"
		    
	hostnames=$(jq -r '.data.hostnames[0] | keys[] | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	hostnames="${hostnames//,/}"
		    
	totalr=$(jq -r '.data."totalReports"' temp.json 2> /dev/null)        
	totalr="${totalr//,/}"
		    
	ndu=$(jq -r '.data."numDistinctUsers"' temp.json 2> /dev/null)        
	ndu="${ndu//,/}"
		    
	lra=$(jq -r '.data."lastReportedAt" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	lra="${lra//,/}"
		    
	ra=$(jq -r '.data.reports[0]."reportedAt" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	ra="${ra//,/}"
		    
	#comment=$(jq -r '.data.reports[0]."comment" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	#comment="${comment//,/}"
		    
	cat=$(jq -r '.data.reports[0].categories[0] | keys[] | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	cat="${cat//,/}"
		    
	ri=$(jq -r '.data.reports[0]."reportedId"' temp.json 2> /dev/null)        
	ri="${ri//,/}"
		    
	rcc=$(jq -r '.data.reports[0]."reporterCountryCode" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	rcc="${rcc//,/}"
		    
	rcn=$(jq -r '.data.reports[0]."reporterCountryName" | gsub("[\\n\\t]"; "")' temp.json 2> /dev/null)        
	rcn="${rcn//,/}"


	echo -e "$ip,$score,,,$cc,$cn,$isp,$domain,$ispub,$ipv,$iswhi,$ut,$hostnames,$totalr,$ndu,$lra,$ra,$cat,$ri,$rcc,$rcn\n"  >> IP_Abuseip_Stats.csv
		    
	if (( $s != 0 ))
	    then  
		 echo -e "===================================================================================================AbuseIP FLAGGED\n"
	fi
        
fi

done < Filtered_Sorted_IPdump

echo -e "\n\n***********************COMPLETED!. Check IP_Abuseip_Stats*************************\n"




#==========VirusTotal
Vapikey=("49858c37eb67ff5a1d1f3785e7a9fc06462e097e3a3cfc8a5b2bf6e7d9fb60d4"
        "3dda53c99e64d05a2041b439a20b566612fec65f4c67566d734bbfd71b880ac3"
        "805f16812921f8b6ba9d535cabf532930629f569e5f26051027000cf0234222a"
        "897ed6ea07a01b7582491a83d1209e10f2fe9af6ff5a6451881cf58190555837"
        "2867273c2b6734677bfe40ed7639292ef3e99699272a61df2bbabaf1907f722c")
Vcount=0

Vagents=$(curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/127.0.0.1 --header 'x-apikey: 49858c37eb67ff5a1d1f3785e7a9fc06462e097e3a3cfc8a5b2bf6e7d9fb60d4' | jq '.data.attributes.last_analysis_results | keys[]')
Vagents="${Vagents[@]// /}"

echo -e "IP","Flagged","Agents\n" >> Virustotal_Stats.csv
ipcount=0

while read line; do
    Vfinal=()
    ipcount=$(( ipcount+1 ))
    echo "[V$ipcount] --------------------------------"$line"--------------------------------------"
    curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' > temp.json
    sed 's/ //g' temp.json > temp2.json
    s=$(jq '.data.attributes.last_analysis_stats.malicious' temp2.json)
    
    if ! [[ "$s" =~ ^[0-9]+$ ]]  #TRY AGAIN ONCE
    then
    	  echo -e "\nRetrying\n"
          curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' > temp.json
          sed 's/ //g' temp.json > temp2.json
          s=$(jq '.data.attributes.last_analysis_stats.malicious' temp2.json)
    fi

    echo $s
    if ! [[ "$s" =~ ^[0-9]+$ ]]
    then
           Vcount=$(( Vcount+1 ))
           s=$(curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' | jq -r '.data.attributes.last_analysis_stats.malicious')
           curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' > temp2.json
           if ! [[ "$s" =~ ^[0-9]+$ ]]  #checking if another key is also not giving null value. Otherwise using another key
           then
                Vcount=$(( Vcount+1 ))
                s=$(curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' | jq -r '.data.attributes.last_analysis_stats.malicious')
                curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' > temp2.json


                if ! [[ "$s" =~ ^[0-9]+$ ]]  #checking if another key is also not giving null value. Otherwise using another key
                then
                        Vcount=$(( Vcount+1 ))
                        s=$(curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' | jq -r '.data.attributes.last_analysis_stats.malicious')
                        curl --request GET --url https://www.virustotal.com/api/v3/ip_addresses/$line --header 'x-apikey: '${Vapikey[$Vcount]}'' > temp2.json

                fi
           fi
    fi
#=========================================================================== IF ONE KEY FAILS THEN OTHER KEY WILL BE USED
#REMOVE FOR LOOP
echo -e "\n\n"
if (( $s != 0 ))
    then
        echo -e  "IP: " $line  "  Total flagged: " $s >> IP_Virustotal_Stats
        for i in ${Vagents[@]}
        do
          stats=".data.attributes.last_analysis_results.$i.result"
          status=$(jq -r  $stats temp2.json)

          if [[ "$status" = "clean" || "$status" = "unrated" ]]
          then
                  cd .
          else
               engine=".data.attributes.last_analysis_results.$i.engine_name"
               agent=$(jq -r $engine temp2.json)
               echo  "Agent: " $agent  "  |    Status: " $status  >> IP_Virustotal_Stats
	       res=$agent:$status
	       Vfinal[${#Vfinal[@]}]=$res
          fi
        done
	echo -e "$line,$s,${Vfinal[@]},\n" >> Virustotal_Stats.csv
	echo -e "\n\n" >> IP_Virustotal_Stats
	echo -e "===================================================================================================Virustotal FLAGGED\n"
fi
done < Filtered_Sorted_IPdump


echo -e "\n\n***********************COMPLETED!. Check IP_Virustotal_Stats*************************\n\n"



rm -rf temp.json IP_Virustotal_Stats temp2.json


fdate=$(date)
echo "Started at: $idate   Finished at: $fdate"

