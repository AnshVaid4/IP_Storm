#This script is created on Python 3.8.10
import csv

nf=""
file =  open("Malicious.csv","a")
file.write("IP_Address,AbuseIPScore,VirustotalScore,VirustotalAgents,CountryCode,CountryName,ISP,Domain,IsPublic,IPversion,IsWhitelisted,UsageType,Hostnames,TotalReports,NumberOfDistictUsers,LastReportedAt,ReportedAt,Categories,ReportedID,ReporterCountryCode,ReporterCountryName\n")

with open('Final.csv') as fileObject:
    reader_obj = csv.reader(fileObject)
    for row in reader_obj:
        try:
            if (row[1]!= None  and row[1]!= "" and int(row[1]) >0) or (row[2] != None and row[1]!= "" and int(row[2]) >0):
                x=(",".join(row))+"\n"
                file.write(x)
        except:
            pass
file.close()
            
