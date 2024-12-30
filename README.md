# WGMY2024-CTF

Hello and welcome to my writeup for CTF WargamesMY 2024!
This year, I participated in the International Open Division with a random team due to last minute registration. despite the chaotic, i managed to solve all forensic challenges, solve all game challenges, solve several misc challenges.

Unfortunately, I could not solve any web and blockchain challenge this time, which motivates me to sharpen my skills in that area.
I hope you enjoy reading this simple writeup.
Happy hacking and learning!

![image](https://github.com/user-attachments/assets/ed4308e2-4db7-4d3c-b2c1-dd17c31dd372)

## Table of contents

| Challenge Solved | Category |
| ---------------- | -------- |
| [1. I Cant Manipulate People](#1-i-cant-manipulate-people-forensic) | Forensic |
| [2. Oh Man](#2-oh-man-forensic) | Forensic |
| [3. Tricky Malware](#3-tricky-malware-forensic) | Forensic |
| [4. Unwanted Meow](#4-unwanted-meow-forensic) | Forensic |
| [5. World 1](#5-world-1-game) | Game |
| [6. World 2](#6-world-2-game) | Game |
| [7. World 3](#7-world-3-game) | Game |
| [8. Christmas GIFt](#8-christmas-gift-misc) | Misc |
| [9. Invisible Ink](#9-invisible-ink-misc) | Misc |
| [10. The DCM Meta](#10-the-dcm-meta-misc) | Misc |

## Challenge Solved

### 1. I Cant Manipulate People (Forensic)

#### Descriptions

Open the provided `traffic.pcap` file in [Wireshark](https://www.wireshark.org/download.html). Apply filter icmp to display only ICMP packets. Examine the data field in the packet details pane will notice a single letter. Manually extract the letters from each packet in the sequence they appear. Combine the extracted letters to form the flag.

#### Steps

1. filter icmp protocol

![image](https://github.com/user-attachments/assets/54a60b15-28ca-405f-9c3c-bd286f434f21)

2. one letter appeared

![image](https://github.com/user-attachments/assets/a5ab9574-56e0-4ed9-9044-341cec500264)

3. flag: `WGMY{1e3b71d57e466ab71b43c2641a4b34f4}`

### 2. Oh Man (Forensic)

#### Descriptions

Open [Online PCAP Analysis](https://apackets.com/upload) and upload the file `wgmy-ohman.pcapng` for analysis. Examine the parsed data and got interesting credentials hash **NTLMSSP authentication**. Use [Hashcat](https://hashcat.net/hashcat/) to crack the hash and the password retrieved is `password<3`. Open the `wgmy-ohman.pcapng` file in [Wireshark](https://www.wireshark.org/download.html). Apply the cracked password `password<3` in the **NTLMSSP protocol** to decrypt the packets. Export all the reconstructed files from the decrypted traffic in [Wireshark](https://www.wireshark.org/download.html). Two Interesting files are `20241225_1939.log` and `RxHmEj`. Open `20241225_1939.log` in [hex editor](https://mh-nexus.de/en/hxd/). The file header is broken and fix it by adding string `MDMP` at the beginning of the file. Run [pypykatz](https://github.com/skelsec/pypykatz) to extract information from the repaired log file. Review the output to extract sensitive information, including the flag.

#### Steps

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

#### Steps

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

#### Steps

1. run `file flag.shredded`

![image](https://github.com/user-attachments/assets/980faa51-2a5f-45b6-b194-954960d880a4)

2. open using hex editor

![image](https://github.com/user-attachments/assets/926742c5-8024-4033-a2c7-8e3c2fa22c38)

3. pyhton script to remove strings meow

```python
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

### 5. World 1 (Game)

#### Descriptions

For safety, execute `World I.exe` in a sandboxed virtual machine. Analyzing the game, recognizing its game engine from a previous CTF. Played the game to its final stage but consistently lost to the last boss. Locate the save game file. Modify the save data to boost the character power and ensure victory using this [RPG MAKER MZ SAVE EDITOR](https://www.save-editor.com/tools/rpg_tkool_mz_save.html). There are five part of flag. Part 1, Defeat the first boss to obtain the flag dropped as an item. Part 2, Defeat the second boss to collect another dropped item containing the flag. Part 3, After defeating the third boss, interact with a chest in the game to obtain the flag. Part 4, locate the flag at specific terrain spot in the volcano map after defeating the fourth boss. Part 5, Defeat the final boss to access a chest requiring a password. Enter the password `wgmy` to retrieve the flag and flag dropped as an item in qr code. Merge all five parts to form the full flag.

#### Steps

1. edit the savegame using [RPG MAKER MZ SAVE EDITOR](https://www.save-editor.com/tools/rpg_tkool_mz_save.html)

![image](https://github.com/user-attachments/assets/03f769fc-80ef-4cbf-89c5-1df404671998)

2. item dropped after defeat the boss

![image](https://github.com/user-attachments/assets/662072d5-b4e3-4378-9d0a-8925431d0e35)

3. part 1 `wgmy{5ce`

![image](https://github.com/user-attachments/assets/6836e3f5-4dee-4942-96b4-f38d939f5591)

4. part 3 `ebabf5cd`

![image](https://github.com/user-attachments/assets/5d8b7d8d-7ae6-4a16-8c39-51dd4cbb0d3a)

5. part 4 `43effd`

![image](https://github.com/user-attachments/assets/5b21876a-f1b5-4c68-b7ac-ccc0a7935bd3)

6. interact to the npc after defeat the last boss

![image](https://github.com/user-attachments/assets/2c3dc3e4-2c0c-4a7d-a549-9f1611d9edd4)

7. entering password for chest

![image](https://github.com/user-attachments/assets/9ba0c5ee-a5c9-4691-b8ef-06e222f0a4a4)

8. password correct

![image](https://github.com/user-attachments/assets/5885b427-5d9c-4b72-bff9-327ec700619c)

9. collection of item after defeat the last boss

![image](https://github.com/user-attachments/assets/b9db7d60-d9f2-4ff6-befb-088794e87697)

10. part 2 `7d7a7140`

![image](https://github.com/user-attachments/assets/d63a79d9-d9ea-427f-8c76-b3343e1305ac)

11. part 5 `3fcaac2}`

![image](https://github.com/user-attachments/assets/bea7f488-ea59-4a96-bec0-97225bf65a01)

12. flag: `wgmy{5ce7d7a7140ebabf5cd439ffd3fcaac2}`

### 6. World 2 (Game)

#### Descriptions

Run the APK file `World_II.apk` on an Android emulator [MEmu](https://www.memuplay.com/). Recognize that the gameplay is similar to the previous challenge. Part 1, Defeat the first boss to obtain the flag as a dropped item. Part 2, Defeat the second boss to collect another dropped item containing the flag. Part 3, After defeating the third boss, interact with the chest in-game to retrieve the flag. Part 4, Locate the flag at a specific terrain spot on the volcano map after defeating the fourth boss. Part 5, different approach to the previous writeups by extract the APK file contents using [online decompiler](https://www.decompiler.com/). Navigate to the directory containing the assets `\assets\www\img\pictures\` located a QR code file named `QR Code 5A.png_`. Upload `QR Code 5A.png_` to an [online decrypter](https://petschko.org/tools/mv_decrypter/#restore-images). Extract the Part 5 of the flag embedded within the QR code. Merge all five parts obtained from the gameplay and QR code extraction to form the complete flag.

#### Steps

1. part 1 `wgmy{406`

![image](https://github.com/user-attachments/assets/3caf3bac-cfe5-4b51-b702-99c9b383dd98)

2. part 2 `8a87d81d`

![image](https://github.com/user-attachments/assets/490da1f4-035b-43c6-88da-82ce9ce1fe7f)

3. part 3 `8c901043`

![image](https://github.com/user-attachments/assets/82aa6667-a09d-478e-8a5f-b7a99b88a0ca)

4. part 4 `885bac`

![image](https://github.com/user-attachments/assets/beba8cd3-e90e-4583-9be2-ae8e66f523de)

5. part 5 `4f51785}`

![QR Code 5A](https://github.com/user-attachments/assets/00653df3-ee60-4ada-9728-12d010365349)

6. luckily I got first blood for this challenge

![image](https://github.com/user-attachments/assets/6912989e-3559-4071-ba2a-6780b0eb5cfe)

7. flag: `wgmy{4068a87d81d8c901043885bac4f51785}`

### 7. World 3 (Game)

#### Descriptions

Open the game in browser and use Inspect Element to analyze its structure. Discover that the game is embedded via an iframe. Navigate to the iframe source to locate the game's JavaScript files for further examination. Identify the interesting code snippet in one of the JS files. Focus the `$dataWeapons` array to manipulate the in-game weapon stats. use the following payload to maximize the weapon's power `$dataWeapons[5].params = [999, 999, 999, 999, 999, 999, 999, 999];`. Inject the payload using browser developer console. The modified weapon allows your character to deal massive damage. Progress through the game and defeat all bosses effortlessly. Each part of flag still the same spot from previous challenge. Merge the collected parts to form the complete flag.

#### Steps

1. interesting code snippet

![image](https://github.com/user-attachments/assets/f5ff9484-0d98-4772-bc9a-f0c3f27a94d7)

2. inject payload `$dataWeapons[5].params = [999, 999, 999, 999, 999, 999, 999, 999];`

![image](https://github.com/user-attachments/assets/607ab68f-fd4e-44c0-963f-2e90a3fbfbf4)

3. part 1 `wgmy{811`

![image](https://github.com/user-attachments/assets/03a64b6e-1284-417e-ac5c-34e3d81a8c8e)

4. part 2 `a332e71b`

![image](https://github.com/user-attachments/assets/b948da55-9bf1-4f72-bbdd-59405ea0573c)

5. part 3 `5d4651ed`

![image](https://github.com/user-attachments/assets/c00f6d98-35b8-4810-bf5b-640132636c83)

6. part 4 `d3ddca`

![image](https://github.com/user-attachments/assets/a267a3a8-be7e-489a-b9ff-78184e5a4244)

7. part 5 `ce5b748)`

![image](https://github.com/user-attachments/assets/838a876e-2c57-41db-842b-db9a18bfdff2)

8. flag: `wgmy{811a332e71b5d4651edd3ddcace5b748}`

### 8. Christmas GIFt (Misc)

#### Descriptions

Launch [stegsolve.jar](https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve/stegsolve.jar). Open the `gift.gif` file. Switch to the Frame Browser tab. Use the left arrow button at the bottom of the interface to scroll the last frames. The flag directly visible.

#### Steps

1. switch to frame browser in stegsolve.jar 

![image](https://github.com/user-attachments/assets/563af3a1-54c5-455e-ba3e-6f4b68f3df84)

2. navigate to the last frame

![image](https://github.com/user-attachments/assets/65619960-922f-4334-83ff-75db1a8986ec)

4. flag: `wgmy{1eaa6da7b7f5df6f7c0381c8f23af4d3}`

### 9. Invisible Ink (Misc)

#### Descriptions

Launch [stegsolve.jar](https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve/stegsolve.jar). Open the `challenge.gif` file. Navigate to Frame 5 and Frame 6. Save these frames individually using the "Save Frame" option in stegsolve. Use stegsolve's color filter modes (e.g., grayscale, red channel, blue channel) on both frames to highlight any obscured text. Use stegsolve’s Image Combiner tool. After combining the images, the hidden text also a flag should become clearer. 

#### Steps

1. extract image using stegsolve

![image](https://github.com/user-attachments/assets/606f6377-a999-4426-8e96-7cca70d3a294)

2. apply colour filter

![image](https://github.com/user-attachments/assets/e08850a4-3029-471f-8198-49fe8009d001)

3. combine two images

![image](https://github.com/user-attachments/assets/0c07ea2d-6b2f-4aaf-b1b0-2ccb8647fd2e)

4. flag: `wgmy{d41d8cd98f00b204e9800998ecf8427e}`

### 10. The DCM Meta (Misc)

#### Descriptions

Given a file `challenge.dcm` and a set of element numbers, likely indices. Read the binary content of the `challenge.dcm` file. By helping from my brother GPT,the script locate specific patterns and extract elements based on the indices. Combine the extracted elements to form the flag.

#### Steps

1. binary content of the `challenge.dcm`

![image](https://github.com/user-attachments/assets/fbf54bc9-ae63-4334-bb9a-73ab76c25bd9)

2. a set of element numbers, likely indices

![image](https://github.com/user-attachments/assets/8bdd5eb4-e917-46ca-8551-b3b12cc3da6d)

3. solve python script

```python
from typing import List

def extract_flag(file_path: str, indices: List[int]) -> str:
    # Open the file in binary mode and read its content
    with open(file_path, 'rb') as file:
        file_content = file.read()

    # Locate the start of the flag (e.g., "WGMY")
    elements = []
    offset = file_content.find(b'WGMY') + 4  # Start reading after "WGMY"
    
    # Extract alphanumeric characters following "WGMY"
    while offset < len(file_content):
        element = file_content[offset:offset + 1].decode(errors='ignore')  # Decode bytes to string
        if element.isalnum():  # Include only alphanumeric characters
            elements.append(element)
        offset += 4  # Move to the next element based on observed pattern
    
    # Use the given indices to extract specific elements
    flag_elements = [elements[i] for i in indices]

    # Combine the extracted elements to form the flag
    flag = "wgmy{" + "".join(flag_elements) + "}"
    return flag

# Example usage
file_path = 'challenge.dcm'
indices = [25, 10, 0, 3, 17, 19, 23, 27, 4, 13, 20, 8, 24, 21, 31, 15, 7, 29, 6, 1, 9, 30, 22, 5, 28, 18, 26, 11, 2, 14, 16, 12]
flag = extract_flag(file_path, indices)
print(flag)

```

4. flag: `wgmy{51fadeb6cc77504db336850d53623177}`
