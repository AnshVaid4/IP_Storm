#This script is created on Python 3.8.10
import csv

nf=""
file =  open("Final.csv","a")
with open('IP_Abuseip_Stats.csv') as fileObjectAB:
    reader_objAB = csv.reader(fileObjectAB)
    for ABrow in reader_objAB:
        flag=0
        ABip=ABrow[0]
        #print(ABip)
        with open('Virustotal_Stats.csv') as fileObjectVT:
            reader_objVT = csv.reader(fileObjectVT)
            for VTrow in reader_objVT:
                VTip=VTrow[0]
                if VTip==ABip:
                    ABrow[2]=VTrow[1]
                    ABrow[3]=VTrow[2]
                    ABs=(",".join(ABrow))+"\n"
                    file.write(ABs)
                    flag=1
            if flag==0:
                ABs=(",".join(ABrow))+"\n"
                file.write(ABs)
file.close()
            
