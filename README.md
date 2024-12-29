# WGMY2024-CTF

Hello and welcome to my writeup for CTF WargamesMY 2024!
This year, i participated in the International Open Division with a random team due to last minute registration. despite the chaotic, i managed to solve all game challenges, solve all forensic challenge, solve several misc challenge.

Unfortunately, I could not solve any web and blockchain challenge this time, which motivates me to sharpen my skills in that area.
I hope you enjoy reading this simple writeup.
Happy hacking and learning!

![image](https://github.com/user-attachments/assets/ab082c26-f71e-472f-8c0f-1195757539ec)

## Challenge Solved

### 1. I Cant Manipulate People (Forensic)

#### Descriptions

Open the provided `traffic.pcap` file in [Wireshark](https://www.wireshark.org/download.html). Apply filter icmp to display only ICMP packets. Examine the data field in the packet details pane will notice a single letter. Manually extract the letters from each packet in the sequence they appear. Combine the extracted letters to form the flag.

#### Steps

1. filter icmp protocol

![image](https://github.com/user-attachments/assets/54a60b15-28ca-405f-9c3c-bd286f434f21)

2. one letter appeared

![image](https://github.com/user-attachments/assets/a5ab9574-56e0-4ed9-9044-341cec500264)

3. flag :`WGMY{1e3b71d57e466ab71b43c2641a4b34f4}`

### 2. Oh Man (Forensic)

#### Descriptions

Open [Online PCAP Analysis](https://apackets.com/upload) and upload the file `wgmy-ohman.pcapng` for analysis. Examine the parsed data and got interesting credentials hash **NTLMSSP authentication**. Use [Hashcat](https://hashcat.net/hashcat/) to crack the hash and the password retrieved is `password<3`. Open the `wgmy-ohman.pcapng` file in [Wireshark](https://www.wireshark.org/download.html). Apply the cracked password `password<3` in the **NTLMSSP protocol** to decrypt the packets. Export all the reconstructed files from the decrypted traffic in [Wireshark](https://www.wireshark.org/download.html). Two Interesting files are `20241225_1939.log` and `RxHmEj`. Open `20241225_1939.log` in [hex editor](https://mh-nexus.de/en/hxd/). The file header is broken and fix it by adding string `MDMP` at the beginning of the file. Run [pypykatz](https://github.com/skelsec/pypykatz) to extract information from the repaired log file. Review the output to extract sensitive information, including the flag.

### Steps

1. Upload and find interesting credentials hash

![image](https://github.com/user-attachments/assets/412a2564-224f-4fdc-a660-40679dd9a9d2)

2. crack the hash using hashcat

![image](https://github.com/user-attachments/assets/b5a659ee-62e8-44a5-9c1f-79e7d0709cb8)

3. apply the password at NTLMSSP

![image](https://github.com/user-attachments/assets/63c109a2-0680-4795-85ec-1e64285fad26)

4. export all the files

![image](https://github.com/user-attachments/assets/7bc6d311-3485-455a-b450-53a675ce026a)

5. interesting file RxHmEj

![image](https://github.com/user-attachments/assets/17fec123-e8c7-4d4a-bc55-accb8cc07b2f)

6. repair header file 20241225_1939.log

![image](https://github.com/user-attachments/assets/18fdf302-1178-4ead-981c-ac8534fc5041)

7. run `pypykatz lsa minidump 20241225_1939.log` and retrived the flag

![image](https://github.com/user-attachments/assets/184eec1a-4668-4b2e-9e19-8873e18f11e8)

8. flag: `wgmy{fbba48bee397414246f864fe4d2925e4}`

### 3. Tricky Malware (Forensic)

#### Descriptions

Open the file `memdump.mem` using [MemProcFS](https://github.com/ufrisk/MemProcFS) to create a virtual drive. Inspect the virtual drive for suspicious files or processes. Identify a suspicious file named `crypt.exe`. Tried to decrypt `crypt.exe` but was unsuccessful. Afterthat, open the file `network.pcap` using [Online PCAP Analysis](https://apackets.com/upload) got interesting network to the `pastebin.com`. Tried to cross-check with memory dump by run strings and grep `pastebin.com` reveals a link to pastebin page. Open the link to obtain the direct flag.

### Steps

1. load MemProcFS file memdump.mem

![image](https://github.com/user-attachments/assets/5757e477-e43d-44f7-9bc7-c52a81d9f0e9)

2. Identify suspicious file crypt.exe

![image](https://github.com/user-attachments/assets/bdfdf03f-ae29-48de-bef5-4962dcdd4433)

3. after failed to decrypt the suspicious file i tried to upload file network.pcap to Online PCAP Analysis

![image](https://github.com/user-attachments/assets/949d2314-d52b-431b-ba7f-ce2fd8b76791)

4. cross-check with memory dump run `strings memdump.mem | grep 'pastebin.com'` found the the link

![image](https://github.com/user-attachments/assets/cf627fdd-2ce9-44cb-8232-d165745d7764)

5. open it to get flag

![image](https://github.com/user-attachments/assets/c1218553-078a-40fc-9cb7-1a9cf941cd7b)

6. flag: `WGMY{8b9777c8d7da5b10b65165489302af32}`

### 4. Unwanted Meow (Forensic)

#### Descriptions

Run the file command on the provided file to identify its type. Suspecting it might be an image, change the file extension to `.jpg` and try opening it. The file fails to load as an image. Open the file in [hex editor](https://mh-nexus.de/en/hxd/). Discovered suspicious strings, such as `meow`. scattered throughout the file. Create a script to remove all occurrences of the meow string and recontruct the file. After running the script, obtain a clear image file. Open the image, which now loads correctly. The flag is embedded within in the images.

### Steps

1. run `file flag.shredded`

![image](https://github.com/user-attachments/assets/980faa51-2a5f-45b6-b194-954960d880a4)

2. open using hex editor

![image](https://github.com/user-attachments/assets/926742c5-8024-4033-a2c7-8e3c2fa22c38)

3. pyhton script to remove strings meow

```
# Script to clean the shredded file
input_file = "flag.shredded"
output_file = "flag_cleaned.jpg"

with open(input_file, "rb") as infile:
    data = infile.read()

# Remove all occurrences of "meow"
cleaned_data = data.replace(b"meow", b"")

with open(output_file, "wb") as outfile:
    outfile.write(cleaned_data)

print(f"Cleaned file saved as {output_file}")

```
4. clear image after running the python script

![flag_cleaned](https://github.com/user-attachments/assets/97b30a45-7ba3-47c2-85dc-1ebc44403714)

5. flag: `WGMY{4a4be40c96ac6314e91d93f38043a643}`

### 5.
