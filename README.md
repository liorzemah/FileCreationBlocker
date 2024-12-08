# FileCreationBlocker
FileCreationBlocker is a kernel module that allow you to monitor file creation and block malicious files.
This kernel module intercepts and monitors file creation in a specified directory. It provides functionality to block certain files based on their names

---

## Features
- **Intercept File Creation**: Hooks into the `inode_operations` of a specified directory to monitor and control file creation.
- **Custom Blocking Logic**: Blocks file creation based on specific conditions (e.g., file name contains "malicious").
- **Logging**: Outputs detailed logs for file creation attempts for debugging and monitoring.

---

## Usage

### Prerequisites
1. Ensure you have a Linux kernel build environment set up.
2. The kernel headers must match the running kernel version.

### Build the Module
```bash
make
```

### Load the Module
```bash
sudo insmod main.ko
```
You can edit the directory by replacing WATCHED_DIR definition (the default is "/home").

### Unload the Module
To remove the module and restore the original behavior:
```bash
sudo rmmod main
```

### Check Logs
Logs are written to the kernel log buffer and can be viewed using:
```bash
dmesg | tail
```

---
### Example Scenario
In the Cmakelist you can see a test that load FileCreationBlocker module, the test try to create 3 files when 2 of them contains the kyy word `malicious` in there names. you can see the test will not ley you allocate the malicious files and only the valid one will be created in the watcher directory.
```bash
make test
```

**Tester output**:
```
sudo insmod ./main.ko
sudo dmesg | tail
[ 9671.087190] Module loaded and start listening to /home directory
[ 9671.106977] Restored original inode operations for directory: /home
[ 9671.106977] Module unloaded and original operations restored.
[ 9717.375336] Loading module to intercept file creation under /home direcgtory
[ 9717.375338] Allocate memory for a custom inode_operations structure and copy the original
[ 9717.375339] Custom create hooked.
[ 9717.375339] Original inode operations address: 00000000400f34b1
[ 9717.375340] Custom inode operations address: 00000000ea40e2b3
[ 9717.375340] Hooked inode operations for directory: /home
[ 9717.375340] Module loaded and start listening to /home directory
sudo touch /home/malicious.txt || echo "Fail to create /home/malicious.txt"
touch: setting times of '/home/malicious.txt': No such file or directory
Fail to create /home/malicious.txt
umask 0 | touch /home/valid.txt || echo "Fail to create file in /home/valid.txt"
sudo touch /home/try.malicious.temp || echo "Fail to create file in /home/try.malicious.temp"
touch: setting times of '/home/try.malicious.temp': No such file or directory
Fail to create file in /home/try.malicious.temp
sudo rmmod main
sudo dmesg | tail
[ 9717.375340] Hooked inode operations for directory: /home
[ 9717.375340] Module loaded and start listening to /home directory
[ 9717.386892] Custom create operation triggered for file: malicious.txt, mode: 33206
[ 9717.386892] Block file: malicious.txt
[ 9717.388492] Custom create operation triggered for file: valid.txt, mode: 33206
[ 9717.388493] Create file: valid.txt
[ 9717.400733] Custom create operation triggered for file: try.malicious.temp, mode: 33206
[ 9717.400734] Block file: try.malicious.temp
[ 9717.404121] Restored original inode operations for directory: /home
[ 9717.404122] Module unloaded and original operations restored.
   ```
---

## Limitations
- The directory path must be an absolute path.
- If the path is invalid or inaccessible, the module will fail to load.
- The module currently blocks files based on name only. Extend this logic as needed.

---

## Troubleshooting

### Error: `insmod: ERROR: could not insert module`
Check the kernel logs for details:
```bash
dmesg | tail
```

### Debugging
Enable dynamic debug logs for detailed output:
```bash
echo 'module main +p' > /sys/kernel/debug/dynamic_debug/control
```

---

## Author
**Lior Zemah**  
