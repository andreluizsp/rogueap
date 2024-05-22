from scapy.all import *
import numpy as np
from scipy.stats import entropy
import math
import dpkt
import time
import os
import numpy as np
import collections

Tags = ["Dot11EltCountry"]

#REFERENCIA DAS TAGS X ID
#dot11_info_elts_ids = {
#    0: "SSID",
#    1: "Supported Rates",
#    2: "FHset",
#    3: "DSSS Set",
#    4: "CF Set",
#    5: "TIM",
#    6: "IBSS Set",
#    7: "Country",
#    10: "Request",
#    11: "BSS Load",
#    12: "EDCA Set",
#    13: "TSPEC",
#    14: "TCLAS",
#    15: "Schedule",
#    16: "Challenge text",
#    32: "Power Constraint",
#    33: "Power Capability",
#    36: "Supported Channels",
#    37: "Channel Switch Announcement",
#    42: "ERP",
#    45: "HT Capabilities",
#    46: "QoS Capability",
#    48: "RSN",
#    50: "Extended Supported Rates",
#    52: "Neighbor Report",
#    61: "HT Operation",
#    74: "Overlapping BSS Scan Parameters",
#    107: "Interworking",
#    127: "Extended Capabilities",
#    191: "VHT Capabilities",
#    192: "VHT Operation",
#    221: "Vendor Specific" }

classified_pkgs = []

# Exibe o cabecalho do dataset
print("rogue,Dot11EltCountry,RSNVersion,rates,CapabilitiesMin_MPDCU_Start_Spacing,DSSS_CCK,Max_A_MSDU,Rx_STBC,Tx_STBC,Short_GI_40Mhz,Short_GI_20Mhz,SM_Power_Save,Supported_Channel_Width,LDPC_Coding_Capability,Min_MPDCU_Start_Spacing,Max_A_MPDU_Length_Exponent,TX_MCS_Set_Defined,RX_MSC_Bitmask,Compressed_Steering_n_Beamformer_Antennas_Supported,Receive_NDP,entropy")
list_files = os.listdir()
for filepcap in list_files:
    if filepcap.endswith('.pcap'):
       #seleciona amostra Hard e Soft AP
       Rogue = "Beacon_Rogue"
       if Rogue not in filepcap:
           line = "0"
       else:
           line = "1"
       for packet in PcapReader(filepcap):
           #teste = packet.getlayer(Dot11Beacon)
           #print(teste)
           for count in range(0,len(Tags)):
               if packet.haslayer(Tags[count]):
                  line = line + ",1"
               else:
                  line = line + ",0"
           try:
               packet[Dot11EltRSN].version
               line = line + ",1" 
               # Versão do Robust Secure Network
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string =  str(packet[Dot11EltRates].len)
               line = line + "," + string
               classified_pkgs.append(string)
               # número de Frequencias suportadas
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Min_MPDCU_Start_Spacing)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].DSSS_CCK)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Max_A_MSDU)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Rx_STBC)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Tx_STBC)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Short_GI_40Mhz)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Short_GI_20Mhz)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].SM_Power_Save)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
           try:
               string = str(packet[Dot11EltHTCapabilities].Supported_Channel_Width)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].LDPC_Coding_Capability)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
           try:
               string = str(packet[Dot11EltHTCapabilities].Min_MPDCU_Start_Spacing)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Max_A_MPDU_Length_Exponent)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].TX_MCS_Set_Defined)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].RX_MSC_Bitmask)
               line = line + "," + "1"
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Compressed_Steering_n_Beamformer_Antennas_Supported)
               line = line + "," + string
               classified_pkgs.append(string)
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           try:
               string = str(packet[Dot11EltHTCapabilities].Receive_NDP)
               line = line + "," + string
           except:
               line = line + ",0"
               classified_pkgs.append(0)
           counter = collections.Counter(classified_pkgs)
           counts  = np.array(list(counter.values()),dtype=float)
           prob = counts/counts.sum()
           shannon_entropy = (-prob * np.log2(prob)).sum()
           line = line + "," + str(shannon_entropy)
           print(line)
           break
#("rogue,Dot11Beacon,Dot11EltRates,Dot11EltDSSSet,Dot11EltCountry,Dot11Elt,Dot11EltRSN,Dot11EltERP,Dot11EltHTCapabilities,Dot11EltVendorSpecific,RSNVersion")
