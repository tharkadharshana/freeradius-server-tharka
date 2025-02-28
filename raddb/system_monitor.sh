#!/bin/bash

LOGFILE="system_monitor.log"

# Install required tools
# sudo apt update && sudo apt install -y sysstat ifstat

# Start monitoring
while true; do
    echo "==========================" >> $LOGFILE
    echo "Timestamp: $(date '+%Y-%m-%d %H:%M:%S')" >> $LOGFILE

    echo "--- CPU Usage (per core) ---" >> $LOGFILE
    mpstat -P ALL 1 1 >> $LOGFILE
    
    echo "--- RAM Usage (MB used) ---" >> $LOGFILE
    free -m | awk '/Mem/{print $3 " MB"}' >> $LOGFILE

    echo "--- Network I/O (KB/s) ---" >> $LOGFILE
    ifstat -q 1 1 | tail -n 1 >> $LOGFILE

    echo "--- Disk I/O ---" >> $LOGFILE
    iostat -d 1 1 >> $LOGFILE

    echo -e "\n" >> $LOGFILE
done
