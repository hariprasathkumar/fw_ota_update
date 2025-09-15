# fw_ota_update
Web -> OTA -> Client (pi) -> DFU

# Firmware OTA Update System

This project implements a simple **Over-The-Air (OTA) firmware update flow** using a **Flask server (PC side)** and a **Flask client (Raspberry Pi side)** that interfaces with a custom Linux kernel driver via sysfs.

---

##  Overview

- **Server (PC)**  
  - Hosts firmware and key files.  
  - Provides a web interface (`index.html`) to upload firmware/key.  
  - Displays Pi device status and progress.  
  - Sends download instructions to the Pi client.

- **Client (Raspberry Pi)**  
  - Downloads firmware/key from the server.  
  - Verifies SHA256 digest of the files.  
  - Places files under `/lib/firmware/`.  
  - Triggers the kernel driver through `/sys/class/pmic_fw_downloader/.../trigger`.  
  - Reports status/progress via sysfs attributes.

- **Kernel Driver (custom)**  
  - Exposes sysfs entries:
    - `trigger` (write-only) → Starts firmware update process.  
    - `status` (read-only) → Reports update status.  
    - `progress` (read-only) → Reports update percentage.  
  - Handles firmware loading, buffer copy, SHA/HMAC computations.  
  - Transfers segments to device over I²C SMBus block transfers. (Yet to be done)

---
##  Usage

### 1. Run the server (PC)
```bash
cd server
python3 app.py
cd client
python3 client.py
```

### 2. Upload firmware + key

Open the server webpage.
Upload ti_buck_fw.bin and ti_buck_fw_key.bin.
Server sends instructions to Pi client.
Client downloads, verifies, places files in /lib/firmware/, and triggers driver.

/sys/class/pmic_fw_downloader/ti-buck-regulator-pmbus-iv/
├── trigger   (write-only)
├── status    (read-only)
└── progress  (read-only)

### 3. Build kernel module for pi
make
sudo insmod pmic_fw_downloader.ko


