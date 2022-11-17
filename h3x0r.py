#!/usr/bin/env python3
import datetime
import os
import random
import re
import string
import webbrowser
from tkinter import StringVar, Text, PhotoImage, IntVar, Menu, BooleanVar
from tkinter.filedialog import asksaveasfile, askopenfilename
from tkinter.messagebox import askokcancel
from tkinter.ttk import *

import _tkinter
import pyperclip
import requests
from ttkbootstrap import Window, Toplevel
from ttkbootstrap.scrolled import ScrolledFrame
from ttkbootstrap.toast import ToastNotification
from ttkbootstrap.tooltip import ToolTip

from logo import png256x256
from modules.Binary import Binary_encrypt, Binary_decrypt
from modules.hAES128 import AES128_Encryption, AES128_Decryption
from modules.hAdler32 import Adler_32
from modules.hBase16 import Encode_base16, Decode_base16
from modules.hBase32 import Encode_base32, Decode_base32
from modules.hBase58 import Encode_base58, Decode_base58
from modules.hBase64 import Encode_base64, Decode_base64
from modules.hBase64_urlsafe import Encode_base64_urlsafe, Decode_base64_urlsafe
from modules.hBase85 import Encode_base85, Decode_base85
from modules.hBcrypt import Bcrypt_Encryption
from modules.hBlack2b import Black2b
from modules.hBlack2s import Black2s
from modules.hBraille import Braille
from modules.hCaesar import Caesar_encode, Caesar_decode
from modules.hCmac import Cmac
from modules.hColors import Hex2Color, Hex2RGB, Color2Hex, RGB2Hex, Color2RGB, RGB2Color
from modules.hCrc16 import _Crc16_
from modules.hCrc32 import _Crc32_
from modules.hCrc8 import _Crc8_
from modules.hDummy import Encode_dummy, Decode_dummy, global_punctuations, arabic_punctuations
from modules.hHexadecimal import Encode_Hexadecimal, Decode_Hexadecimal
from modules.hHexdump import HexDump
from modules.hHmac import Hmac
from modules.hHtml import HTML_encode, HTML_decode
from modules.hKMAC128 import _KMAC128_
from modules.hKMAC256 import _KMAC256_
from modules.hKeccak224 import Keccak224
from modules.hKeccak256 import Keccak256
from modules.hKeccak384 import Keccak384
from modules.hKeccak512 import Keccak512
from modules.hMd2 import _Md2_
from modules.hMd4 import _Md4_
from modules.hMd5 import Md5
from modules.hMorse import Morse_encode, Morse_decode
from modules.hNtlm import Ntlm
from modules.hPoly1305 import _Poly1305_
from modules.hPunycode import Punycode
from modules.hRipemd160 import Ripemd_160
from modules.hSha1 import Sha1
from modules.hSha224 import Sha224
from modules.hSha256 import Sha256
from modules.hSha384 import Sha384
from modules.hSha3_224 import Sha3_224
from modules.hSha3_256 import Sha3_256
from modules.hSha3_384 import Sha3_384
from modules.hSha3_512 import Sha3_512
from modules.hSha512 import Sha512
from modules.hShake128 import Shake128
from modules.hShake256 import Shake256
from modules.hTimestamp import months_name, Date2Timestamp, Timestamp2Date
from modules.hUrl import Url
from modules.hWhirlpool import Whirlpool
from modules.hZlib import Zlib_compress
from utils import monitor
from versions import version


def Hexor():
    h3x0r = Window(themename='darkly')  # yeti, darkly
    width = monitor(h3x0r)['width']
    height = monitor(h3x0r)['height']
    h3x0r.geometry(f"{width // 2}x{int(height // 1.25)}+{int(width // 3.75)}+{height // 12}")
    icon = PhotoImage(data=png256x256)
    h3x0r.call('wm', 'iconphoto', h3x0r._w, icon)
    h3x0r.title("H3x0r | v%s" % version)

    # if "windows" in platform.platform().lower(): window.state("zoom")

    tooltip_style = "secondary.inverse"

    ###############################################
    menubar = Menu()
    ###############################################

    ###############################################
    Edit_menu = Menu()
    menubar.add_cascade(label="Edit", menu=Edit_menu)
    ###############################################

    ###############################################
    # Action_menu = Menu()
    # menubar.add_cascade(label="Action", menu=Action_menu)
    ###############################################

    ###############################################
    Compare_menubar = Menu()
    menubar.add_cascade(label="Compare", menu=Compare_menubar)

    def Compare_checksum(module: str):
        file1 = askopenfilename(title=f"File 1 ({module.upper().replace('.', ' ')})")
        if file1:
            file2 = askopenfilename(title=f"File 2 ({module.upper().replace('.', ' ')})")
            if file2:
                start = datetime.datetime.now()
                hash1 = execute[module]["checksum"](open(file=file1, mode="rb").read())
                hash2 = execute[module]["checksum"](open(file=file2, mode="rb").read())
                end = str(datetime.datetime.now() - start)

                if hash1 == hash2:
                    ToastNotification(title=f"{module.upper().replace('.', ' ')}",
                                      message=f"file1: {file1}\nfile2: {file2}\nhash: {hash1}\nestimated: {end[:-4]}",
                                      bootstyle="success", icon="✅", duration=0).show_toast()
                else:
                    ToastNotification(title=f"{module.upper().replace('.', ' ')}",
                                      message=f"file1: {file1}\nfile2: {file2}\nhash1: {hash1}\nhash2: {hash2}\nestimated: {end[:-4]}",
                                      bootstyle="danger", icon="❌", duration=0).show_toast()

    Compare_menubar.add_command(label="MD2", command=lambda: Compare_checksum(module="md2"))
    Compare_menubar.add_command(label="MD4", command=lambda: Compare_checksum(module="md4"))
    Compare_menubar.add_command(label="MD5", command=lambda: Compare_checksum(module="md5"))
    Compare_menubar.add_command(label="Sha1", command=lambda: Compare_checksum(module="sha1"))
    Compare_menubar.add_command(label="Sha224", command=lambda: Compare_checksum(module="sha224"))
    Compare_menubar.add_command(label="Sha256", command=lambda: Compare_checksum(module="sha256"))
    Compare_menubar.add_command(label="Sha384", command=lambda: Compare_checksum(module="sha384"))
    Compare_menubar.add_command(label="Sha512", command=lambda: Compare_checksum(module="sha512"))
    Compare_menubar.add_command(label="Sha3-224", command=lambda: Compare_checksum(module="sha3.224"))
    Compare_menubar.add_command(label="Sha3-256", command=lambda: Compare_checksum(module="sha3.256"))
    Compare_menubar.add_command(label="Sha3-384", command=lambda: Compare_checksum(module="sha3.384"))
    Compare_menubar.add_command(label="Sha3-512", command=lambda: Compare_checksum(module="sha3.512"))
    Compare_menubar.add_command(label="SHAKE128", command=lambda: Compare_checksum(module="shake.128"))
    Compare_menubar.add_command(label="SHAKE256", command=lambda: Compare_checksum(module="shake.256"))
    # ----------------------------------------------
    Insert_menu = Menu()
    menubar.add_cascade(label="Insert", menu=Insert_menu)

    def InsertFromFile():
        file = askopenfilename(title="what file?")
        if file:
            if os.path.exists(file):
                content = open(file, 'r', errors="ignore").read()
                if len(content) > 0:
                    input.delete(1.0, 'end')
                    input.insert(1.0, content)
                    Input_Details_Update()
                    Output_Details_Update()

    Insert_menu.add_command(label="File", command=lambda: InsertFromFile())

    # ----------------------------------------------
    def InsertFromUrl():
        topwin = Toplevel()
        icon = PhotoImage(data=png256x256)
        topwin.iconphoto(False, icon)
        topwin.attributes('-topmost', True)
        topwin.attributes('-toolwindow', True)
        topwin.resizable(True, False)
        topwin.title("Insert from a url")

        url = Entry(topwin, bootstyle="info")
        url.pack(side='top', fill='x', expand=True)

        def Confirm():
            try:
                content = requests.get(url.get()).text
                if len(content) > 0:
                    input.delete(1.0, 'end')
                    input.insert(1.0, content)
            except Exception:
                pass
            topwin.destroy()

        confirm = Button(topwin, text="Confirm", cursor="hand2", takefocus=False, command=lambda: Confirm())
        confirm.pack(side='bottom', fill='x', expand=True)
        topwin.mainloop()

    Insert_menu.add_command(label="Url", command=lambda: InsertFromUrl())

    # ----------------------------------------------
    def Exit():
        if askokcancel(title="Are you sure?", message="Nothing will be saved."):
            h3x0r.destroy()

    menubar.add_command(label="Exit", command=lambda: Exit())
    ###############################################

    right_frame = Frame(h3x0r, width=width // 6)
    right_frame.pack(side='right', fill='both')
    left_frame = Frame(h3x0r, width=width // 6)
    left_frame.pack(side='left', fill='both')

    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
    # ----------->                                       <-----------#
    # --------->                 STAGER                    <---------#
    # ----------->                                       <-----------#
    # !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
    # stager_frame = ScrolledFrame(left_frame, bootstyle='secondary', height=height)
    # stager_frame.vscroll.config(bootstyle='light-rounded')
    # stager_frame.pack(fill='both', side='right', expand=True)
    # stages_list = Listbox(stager_frame, font=("' 15"), justify='center', selectmode='single')
    # for i in range(100):stages_list.insert('end', str(random.randint(1111111111,99999999999999999)))
    # stages_list.pack(fill='both', expand=True)
    #################################################################

    settings_frame = ScrolledFrame(left_frame, bootstyle='secondary', height=height)  # , cursor='sb_v_double_arrow')
    settings_frame.vscroll.config(bootstyle='light-rounded')
    # settings_frame.vscroll.pack(side='left')
    # settings_frame.vscroll.pack_forget()
    settings_frame.pack(fill='both', side='left')

    ###########################################################################
    binary_settings_frame = LabelFrame(settings_frame, text="Binary")
    binary_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(binary_settings_frame, text="Separator").pack()
    binary_separators = (" ",) + tuple(string.punctuation)
    binary_separatorVar = StringVar(value=" ")
    binary_separator_combobox = Combobox(binary_settings_frame, state='readonly', textvariable=binary_separatorVar,
                                         values=binary_separators, bootstyle='info')
    ToolTip(binary_separator_combobox, "Binary separator", tooltip_style, alpha=1)
    binary_separator_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    morse_settings_frame = LabelFrame(settings_frame, text="Morse")
    morse_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(morse_settings_frame, text="Separator").pack()
    morse_separators = (
    '/', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', ':', ';', '<', '=', '>', '?', '@',
    '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~')
    morse_separatorVar = StringVar(value=morse_separators[0])
    morse_separator_combobox = Combobox(morse_settings_frame, state='readonly', textvariable=morse_separatorVar,
                                        values=morse_separators, bootstyle='info')
    ToolTip(morse_separator_combobox, "Morse character separator", tooltip_style, alpha=1)
    morse_separator_combobox.pack(side='top', fill='both', padx=10)
    # --------------------------------------------------------------------------
    Label(morse_settings_frame, text="Space").pack()
    morse_spaces = (
    ' ', '/', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', ':', ';', '<', '=', '>', '?', '@',
    '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~')
    morse_spaceVar = StringVar(value=morse_spaces[0])
    morse_space_combobox = Combobox(morse_settings_frame, state='readonly', textvariable=morse_spaceVar,
                                    values=morse_spaces, bootstyle='info')
    ToolTip(morse_space_combobox, "Morse word seperator", tooltip_style, alpha=1)
    morse_space_combobox.pack(side='top', fill='both', padx=10)
    # --------------------------------------------------------------------------
    Label(morse_settings_frame, text="Dot").pack()
    morse_dots = ["•", ".", "○", "∙", "⦿", "⦾", "⚪", "⚫", "◦", "·"]
    morse_dotsVar = StringVar(value=morse_dots[0])
    morse_dots_combobox = Combobox(morse_settings_frame, state='readonly', textvariable=morse_dotsVar,
                                   values=morse_dots, bootstyle='info')
    ToolTip(morse_dots_combobox, "Morse dot", tooltip_style, alpha=1)
    morse_dots_combobox.pack(side='top', fill='both', padx=10)
    # --------------------------------------------------------------------------
    Label(morse_settings_frame, text="Dash").pack()
    morse_dashes = ["—", "–", "―", "‒", "–", "_", "-", "¯", "一", "﹘", "⁃", "⁻", "➖", "⸏", "⸻", "⸺", "⏤", "⎯", "𑁒",
                    "𑁋"]
    morse_dashesVar = StringVar(value=morse_dashes[0])
    morse_dashes_combobox = Combobox(morse_settings_frame, state='readonly', textvariable=morse_dashesVar,
                                     values=morse_dashes, bootstyle='info')
    ToolTip(morse_dashes_combobox, "Morse dash", tooltip_style, alpha=1)
    morse_dashes_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    caesar_settings_frame = LabelFrame(settings_frame, text="Caesar")
    caesar_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(caesar_settings_frame, text="Shifts").pack()
    caesar_shiftsVar = IntVar(value=3)
    caesar_separator_spinbox = Spinbox(caesar_settings_frame, state='readonly', textvariable=caesar_shiftsVar,
                                       takefocus=False, wrap=False, from_=1, to=1000, bootstyle='info')
    ToolTip(binary_separator_combobox, "Caesar shift times", tooltip_style, alpha=1)
    caesar_separator_spinbox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    hexdump_settings_frame = LabelFrame(settings_frame, text="Hexdump")
    hexdump_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(hexdump_settings_frame, text="File").pack()
    hexdump_file_frame = Frame(hexdump_settings_frame)
    hexdump_file_frame.pack(side='top', fill='both', padx=10)
    hexdump_file = Entry(hexdump_file_frame, bootstyle='info')
    ToolTip(hexdump_file, "Hexdump file to dump", tooltip_style, alpha=1)
    hexdump_file.pack(side='left', fill='both', expand=True)

    def HexdumpFilePick():
        file = askopenfilename(title="what file?")
        if file:
            hexdump_file.delete(0, 'end')
            hexdump_file.insert(0, file)

    hexdump_file_pick = Button(hexdump_file_frame, text="..", cursor='hand2', takefocus=False, bootstyle='info',
                               command=lambda: HexdumpFilePick())
    hexdump_file_pick.pack(side='right', fill='both', padx=3)
    # --------------------------------------------------------------------------
    Label(hexdump_settings_frame, text="Module").pack()
    hexdump_types = ("hexadecimal", "binary")
    hexdump_typeVar = StringVar(value=hexdump_types[0])
    hexdump_type_combobox = Combobox(hexdump_settings_frame, state='readonly', textvariable=hexdump_typeVar,
                                     values=hexdump_types, bootstyle='info')
    ToolTip(hexdump_type_combobox, "Hexdump as hexadecimal or binary", tooltip_style, alpha=1)
    hexdump_type_combobox.pack(side='top', fill='both', padx=10)
    # --------------------------------------------------------------------------
    Label(hexdump_settings_frame, text="Fence").pack()
    hexdump_separators = (" ",) + tuple(string.punctuation)
    hexdump_fenceVar = StringVar(value="|")
    hexdump_separator_combobox = Combobox(hexdump_settings_frame, state='readonly', textvariable=hexdump_fenceVar,
                                          values=hexdump_separators, bootstyle='info')
    ToolTip(hexdump_separator_combobox, "Hexdump data fence", tooltip_style, alpha=1)
    hexdump_separator_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    dummy_settings_frame = LabelFrame(settings_frame, text="Dummy")
    dummy_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(dummy_settings_frame, text="Seperator").pack()
    dummy_separators = (" ",) + tuple(global_punctuations) + tuple(arabic_punctuations)
    dummy_separatorVar = StringVar(value=".")
    dummy_separator_combobox = Combobox(dummy_settings_frame, state='readonly', textvariable=dummy_separatorVar,
                                        values=dummy_separators, bootstyle='info')
    ToolTip(dummy_separator_combobox, "Dummy data seperator", tooltip_style, alpha=1)
    dummy_separator_combobox.pack(side='top', fill='both', padx=10)
    # --------------------------------------------------------------------------
    Dummy_en_letters_upperVar = BooleanVar(value=True)
    Dummy_en_letters_upper = Checkbutton(dummy_settings_frame, text="english letters upper",
                                         variable=Dummy_en_letters_upperVar)
    ToolTip(Dummy_en_letters_upper, "English letters (upper)", tooltip_style, alpha=1)
    Dummy_en_letters_upper.pack(side='top', fill='both', padx=10, pady=5, expand=True)
    # --------------------------------------------------------------------------
    Dummy_en_letters_lowerVar = BooleanVar(value=True)
    Dummy_en_letters_lower = Checkbutton(dummy_settings_frame, text="english letters lower",
                                         variable=Dummy_en_letters_lowerVar)
    ToolTip(Dummy_en_letters_lower, "English letters (lower)", tooltip_style, alpha=1)
    Dummy_en_letters_lower.pack(side='top', fill='both', padx=10, expand=True)
    # --------------------------------------------------------------------------
    Dummy_global_punctuationsVar = BooleanVar(value=True)
    Dummy_global_punctuations = Checkbutton(dummy_settings_frame, text="global punctuation",
                                            variable=Dummy_global_punctuationsVar)
    ToolTip(Dummy_global_punctuations, "Global punctuations (all but not other languages punctuations)", tooltip_style,
            alpha=1)
    Dummy_global_punctuations.pack(side='top', fill='both', padx=10, pady=5, expand=True)
    # --------------------------------------------------------------------------
    Dummy_ar_lettersVar = BooleanVar(value=True)
    Dummy_ar_letters = Checkbutton(dummy_settings_frame, text="arabic letters", variable=Dummy_ar_lettersVar)
    ToolTip(Dummy_ar_letters, "Arabic letters", tooltip_style, alpha=1)
    Dummy_ar_letters.pack(side='top', fill='both', padx=10, expand=True)
    # --------------------------------------------------------------------------
    Dummy_ar_numbersVar = BooleanVar(value=True)
    Dummy_ar_numbers = Checkbutton(dummy_settings_frame, text="arabic numbers", variable=Dummy_ar_numbersVar)
    ToolTip(Dummy_ar_numbers, "Arabic numbers", tooltip_style, alpha=1)
    Dummy_ar_numbers.pack(side='top', fill='both', padx=10, pady=5, expand=True)
    # --------------------------------------------------------------------------
    Dummy_ar_punctuationsVar = BooleanVar(value=True)
    Dummy_ar_punctuations = Checkbutton(dummy_settings_frame, text="arabic punctuations",
                                        variable=Dummy_ar_punctuationsVar)
    ToolTip(Dummy_ar_punctuations, "Arabic punctuations", tooltip_style, alpha=1)
    Dummy_ar_punctuations.pack(side='top', fill='both', padx=10, expand=True)
    # --------------------------------------------------------------------------
    Dummy_ar_formattersVar = BooleanVar(value=True)
    Dummy_ar_formatters = Checkbutton(dummy_settings_frame, text="arabic formatters", variable=Dummy_ar_formattersVar)
    ToolTip(Dummy_ar_formatters, "Arabic formatters", tooltip_style, alpha=1)
    Dummy_ar_formatters.pack(side='top', fill='both', padx=10, pady=5, expand=True)

    ###########################################################################

    ###########################################################################
    cmac_settings_frame = LabelFrame(settings_frame, text="CMAC")
    cmac_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(cmac_settings_frame, text="Key").pack()
    cmac_key = Entry(cmac_settings_frame, bootstyle='info')
    ToolTip(cmac_key, "CMAC key (password?!) length must be 16", tooltip_style, alpha=1)
    cmac_key.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    hmac_settings_frame = LabelFrame(settings_frame, text="HMAC")
    hmac_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(hmac_settings_frame, text="Key").pack()
    hmac_key = Entry(hmac_settings_frame, bootstyle='info')
    ToolTip(hmac_key, "HMAC key (password?!)", tooltip_style, alpha=1)
    hmac_key.pack(side='top', fill='both', padx=10)
    # --------------------------------------------------------------------------
    Label(hmac_settings_frame, text="Digest mode").pack()
    hmac_digestmods = ['md5-sha1', 'whirlpool', 'sm3', 'sha512-224', 'mdc2', 'ripemd160', 'md4', 'md5', 'sha1',
                       'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512',
                       'blake2b']
    hmac_digestmodVar = StringVar(value=sorted(hmac_digestmods)[0])
    hmac_digestmod = Combobox(hmac_settings_frame, state='readonly', textvariable=hmac_digestmodVar,
                              values=sorted(hmac_digestmods), bootstyle='info')
    ToolTip(hmac_digestmod, "HMAC digest mode", tooltip_style, alpha=1)
    hmac_digestmod.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    poly1305_settings_frame = LabelFrame(settings_frame, text="Poly1305")
    poly1305_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(poly1305_settings_frame, text="Key").pack()
    poly1305_key = Entry(poly1305_settings_frame, bootstyle='info')
    ToolTip(poly1305_key, "Poly1305 key", tooltip_style, alpha=1)
    poly1305_key.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    shake_settings_frame = LabelFrame(settings_frame, text="Shake128/256")
    shake_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(shake_settings_frame, text="Length").pack()
    shake_lengthVar = IntVar(value=1)
    shake_length = Spinbox(shake_settings_frame, from_=1, to=1000, textvariable=shake_lengthVar, state="readonly",
                           increment=1, bootstyle='info')
    ToolTip(shake_length, "Shake128/256 length", tooltip_style, alpha=1)
    shake_length.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    aes128_settings_frame = LabelFrame(settings_frame, text="AES128")
    aes128_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(aes128_settings_frame, text="Key").pack()
    aes128_key = Entry(aes128_settings_frame, bootstyle='info')
    ToolTip(aes128_key, "Aes128 key", tooltip_style, alpha=1)
    aes128_key.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    html_settings_frame = LabelFrame(settings_frame, text="HTML")
    html_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    # Label(html_settings_frame, text="Quote").pack()
    HTML_quoteVar = BooleanVar(value=True)
    html_quote = Checkbutton(html_settings_frame, text="quote", variable=HTML_quoteVar)
    ToolTip(html_quote, "HTML encode even the quotes \" and \'", tooltip_style, alpha=1)
    html_quote.pack(side='top', fill='both', padx=10, expand=True)
    ###########################################################################

    ###########################################################################
    timestamp_settings_frame = LabelFrame(settings_frame, text="Timestamp")
    timestamp_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(timestamp_settings_frame, text="Year").pack()
    timestamp_yearVar = IntVar(value=datetime.datetime.now().year)
    timestamp_year = Spinbox(timestamp_settings_frame, from_=1, to=3000, textvariable=timestamp_yearVar,
                             state="readonly",
                             increment=1, bootstyle='info')
    timestamp_year.pack(side='top', fill='x', padx=10, expand=True)
    # --------------------------------------------------------------------------
    Label(timestamp_settings_frame, text="Month").pack()
    # ==========================================
    timestamp_month_numberVar = IntVar(value=datetime.datetime.now().month)
    timestamp_month_number = Spinbox(timestamp_settings_frame, from_=1, to=12, textvariable=timestamp_month_numberVar,
                                     state="readonly", increment=1, bootstyle='info')

    def MonthNumber_Changed(*args):
        timestamp_month_nameVar.set(value=months_name[timestamp_month_numberVar.get()])

    timestamp_month_numberVar.trace('w', MonthNumber_Changed)  # w=write, r=read, u=undefine
    timestamp_month_number.pack(side='top', fill='x', padx=10, expand=True)
    # ==========================================
    timestamp_month_nameVar = StringVar(value=months_name[datetime.datetime.now().month])
    timestamp_month_name = OptionMenu(timestamp_settings_frame, timestamp_month_nameVar, direction="above",
                                      *list(months_name.values()))

    def MonthName_Changed(*args):
        timestamp_month_numberVar.set(
            value=list(months_name.keys())[list(months_name.values()).index(timestamp_month_nameVar.get())])

    timestamp_month_nameVar.trace('w', MonthName_Changed)  # w=write, r=read, u=undefine
    timestamp_month_name.pack(side='top', fill='x', padx=10, pady=5, expand=True)
    # --------------------------------------------------------------------------
    Label(timestamp_settings_frame, text="Day").pack()
    timestamp_dayVar = IntVar(value=datetime.datetime.now().day)
    timestamp_day = Spinbox(timestamp_settings_frame, from_=1, to=31, textvariable=timestamp_dayVar, state="readonly",
                            increment=1, bootstyle='info')
    timestamp_day.pack(side='top', fill='x', padx=10, expand=True)
    # --------------------------------------------------------------------------
    Label(timestamp_settings_frame, text="Hour").pack()
    timestamp_hourVar = IntVar(value=datetime.datetime.now().hour)
    timestamp_hour = Spinbox(timestamp_settings_frame, from_=1, to=23, textvariable=timestamp_hourVar, state="readonly",
                             increment=1, bootstyle='info')
    timestamp_hour.pack(side='top', fill='x', padx=10, expand=True)
    # --------------------------------------------------------------------------
    Label(timestamp_settings_frame, text="Minute").pack()
    timestamp_minuteVar = IntVar(value=datetime.datetime.now().minute)
    timestamp_minute = Spinbox(timestamp_settings_frame, from_=1, to=59, textvariable=timestamp_minuteVar,
                               state="readonly",
                               increment=1, bootstyle='info')
    timestamp_minute.pack(side='top', fill='x', padx=10, expand=True)
    # --------------------------------------------------------------------------
    Label(timestamp_settings_frame, text="Second").pack()
    timestamp_secondVar = IntVar(value=datetime.datetime.now().second)
    timestamp_second = Spinbox(timestamp_settings_frame, from_=1, to=59, textvariable=timestamp_secondVar,
                               state="readonly",
                               increment=1, bootstyle='info')
    timestamp_second.pack(side='top', fill='x', padx=10, expand=True)

    ###########################################################################

    ###########################################################################
    zlib_settings_frame = LabelFrame(settings_frame, text="Zlib")
    zlib_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(zlib_settings_frame, text="Level").pack()
    zlib_comp_levelVar = IntVar(value=0)
    zlib_comp_level = Spinbox(zlib_settings_frame, from_=-1, to=9, textvariable=zlib_comp_levelVar,
                              state="readonly",
                              increment=1, bootstyle='info')
    ToolTip(zlib_comp_level, "Zlib compress level", tooltip_style, alpha=1)
    zlib_comp_level.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    replace_settings_frame = LabelFrame(settings_frame, text="Replace")
    replace_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(replace_settings_frame, text="From").pack()
    replace_from = Entry(replace_settings_frame, bootstyle='info')
    ToolTip(replace_from, "Replace from", tooltip_style, alpha=1)
    replace_from.pack(side='top', fill='both', padx=10)
    # --------------------------------------------------------------------------
    Label(replace_settings_frame, text="To").pack()
    replace_to = Entry(replace_settings_frame, bootstyle='info')
    ToolTip(replace_to, "Replace from", tooltip_style, alpha=1)
    replace_to.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    remove_settings_frame = LabelFrame(settings_frame, text="Remove")
    remove_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(remove_settings_frame, text="Character(s)").pack()
    remove_character = Entry(remove_settings_frame, bootstyle='info')
    ToolTip(remove_character, "Remove character", tooltip_style, alpha=1)
    remove_character.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    hashing_settings_frame = LabelFrame(settings_frame, text="Hashing module")
    hashing_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    # --------------------------------------------------------------------------
    Label(hashing_settings_frame, text="Module").pack()
    hashing_types = ("hexdigest", "digest")
    hashing_typeVar = StringVar(value="hexdigest")
    hasing_type_combobox = Combobox(hashing_settings_frame, state='readonly', textvariable=hashing_typeVar,
                                    values=hashing_types, bootstyle='info')
    ToolTip(hasing_type_combobox,
            "hashing module",
            tooltip_style, alpha=1)
    hasing_type_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    icon = PhotoImage(data=png256x256)
    Label(right_frame, bootstyle="danger", justify='center', anchor='center', image=icon).pack(fill='x', ipady=10)
    Hexor_By_SecVirus = Label(right_frame, text="H3x0r By @SecVirus", bootstyle="danger", justify='center',
                              anchor='center', cursor='hand2')
    Hexor_By_SecVirus.bind("<Button-1>", lambda a: webbrowser.open("https://secvirus.w3spaces.com"))
    Hexor_By_SecVirus.pack(fill='x')

    ###########################################################################
    Search_types = Entry(right_frame, bootstyle='light')
    Search_types.pack(side='top', fill='x', padx=3, pady=3)
    search_result = []

    # --------------------------------------------------------------------------
    def Search(event):
        def Enable():
            Search_next.config(state='normal', cursor='hand2')
            Search_previous.config(state='normal', cursor='hand2')
            Search_result_lbl.config(text=search_result[0])
            selected_typeVar.set(value=search_result[0])
            Search_result_details.config(
                text=f"{search_result.index(Search_result_lbl['text']) + 1}/{len(search_result)}")
            type_lbl.config(text='~ ' + selected_typeVar.get().upper() + ' ~')
            Type_changed()
            # types_frame.yview_moveto(
            #     float(
            #         (0.019) *
            #         len(
            #             search_result[
            #                 :search_result.index(
            #                     search_result[0]
            #                 )
            #             ]
            #         )
            #     )
            # )

            # print(types_frame.vscroll.get()[0])
            # print(search_result[0])
            # print(-search_result.index(search_result[0]))
            # print(search_result[:search_result.index(search_result[0])])
            # print(len(search_result[-search_result.index(search_result[0])]))
            # print(float(len(search_result[-search_result.index(search_result[0])])))

        def Disable():
            search_result.clear()
            Search_next.config(state='disabled', cursor='')
            Search_previous.config(state='disabled', cursor='')
            # Search_result_lbl.config(text="Search for module..")
            Search_result_details.config(text=f"")
            Type_changed()

            lf = list(list(types_frame.children.values())[1].children.values())
            for r in lf:  # r=radiobutton
                r.configure(bootstyle='dark-toolbutton')
            type_lbl.config(text="Welcome back!")
            selected_typeVar.set(value="")

        if Search_types.get():
            search_result.clear()
            Search_result_lbl.config(text="Search for module..")
            s = Search_types.get()  # s=search

            lf = list(list(types_frame.children.values())[1].children.values())  # lf=left frame
            for r in lf:  # r=radiobutton
                if s in r['value']:
                    search_result.append(r['value'])
                    r.configure(bootstyle='success-toolbutton-outline')
                else:
                    # ------------------------------------
                    # Restore every module to dark bootstyle
                    # if it's not in search query.
                    # ------------------------------------
                    r.configure(bootstyle='dark-toolbutton')

            if search_result:
                Search_result_lbl.config(bootstyle="success")
                Enable()
            else:
                Search_result_lbl.config(text=f"No result!", bootstyle="danger")
                Disable()
        else:
            Search_result_lbl.config(text=f"Search for module..", bootstyle="light")
            Disable()
        Type_changed()

    Search_types.bind("<KeyPress>", Search)
    Search_types.bind("<KeyRelease>", Search)

    # --------------------------------------------------------------------------
    def Search_Up():
        if search_result:
            try:
                next = search_result[search_result.index(Search_result_lbl['text']) + 1]
                selected_typeVar.set(value=next)
                Search_result_lbl.config(text=next)
                type_lbl.config(text='~ ' + selected_typeVar.get().upper() + ' ~')
                Search_result_details.config(
                    text=f"{search_result.index(Search_result_lbl['text']) + 1}/{len(search_result)}")
                Type_changed()
            except Exception:
                return

    def Search_Down():
        if search_result:
            try:
                if (search_result.index(Search_result_lbl['text']) - 1) > -1:
                    next = search_result[search_result.index(Search_result_lbl['text']) - 1]
                    selected_typeVar.set(value=next)
                    Search_result_lbl.config(text=next)
                    type_lbl.config(text='~ ' + selected_typeVar.get().upper() + ' ~')
                    Search_result_details.config(
                        text=f"{search_result.index(Search_result_lbl['text']) + 1}/{len(search_result)}")
                    Type_changed()
            except Exception:
                return

    # --------------------------------------------------------------------------
    Search_result_frame = Frame(right_frame)
    Search_result_frame.pack(side='top', fill='x', padx=3, pady=3)
    # --------------------------------------------------------------------------
    Search_result_details = Label(Search_result_frame, text="", justify='center', anchor='center')
    Search_result_details.pack(side='bottom', fill='x', expand=True)

    # --------------------------------------------------------------------------
    Search_next = Button(Search_result_frame, text="\u25C0", takefocus=False, command=lambda: Search_Up(),
                         bootstyle='light', state='disabled')
    ToolTip(Search_next, "Next", bootstyle=tooltip_style)
    Search_next.pack(side='left')
    # --------------------------------------------------------------------------
    Search_previous = Button(Search_result_frame, text="\u25B6", takefocus=False, command=lambda: Search_Down(),
                             bootstyle='light', state='disabled')
    ToolTip(Search_previous, "Previous", bootstyle=tooltip_style)
    Search_previous.pack(side='right')
    # --------------------------------------------------------------------------
    Search_result_lbl = Label(Search_result_frame, text="Search for module..", justify='center', anchor='center')
    Search_result_lbl.pack(side='left', fill='x', padx=3, pady=3, expand=True)
    # --------------------------------------------------------------------------

    types_frame = ScrolledFrame(right_frame, bootstyle='secondary', height=height)
    types_frame.vscroll.config(bootstyle='light-rounded')
    types_frame.pack(fill='both')

    workspace_frame = Frame(h3x0r, bootstyle='dark')
    workspace_frame.pack(fill='both', expand=True)

    type_lbl = Label(workspace_frame, text="Welcome back!", font=("' 25"), justify='center', anchor='center',
                     bootstyle='dark.inverse')
    type_lbl.pack(fill='x', side='top')

    ###############################################################################
    input_frame = Frame(workspace_frame)
    input_frame.pack(fill='both', side='top', pady=5, expand=True)
    # ------------------------------------------------------------------------------
    input_text_frame = Frame(input_frame)
    input_text_frame.pack(side='top', fill='both', expand=True)
    # ------------------------------------------------------------------------------
    input_VScroll = Scrollbar(input_text_frame, orient="vertical", bootstyle="light-rounded")
    input_VScroll.pack(side='right', fill='y')
    # ------------------------------------------------------------------------------
    input = Text(input_text_frame, takefocus=True, maxundo=-1, undo=True, wrap="char", yscrollcommand=input_VScroll.set)
    input.pack(fill='both', side='left', expand=True)
    input_VScroll.config(command=input.yview)
    # ------------------------------------------------------------------------------
    input_details_frame = Frame(input_frame)
    input_details_frame.pack(fill='x', side='bottom')
    # ------------------------------------------------------------------------------
    input_last_edit = Label(input_details_frame, text=datetime.datetime.now().strftime("%Y/%m/%d - %I:%M:%S %p"))
    ToolTip(input_last_edit, "Last interaction with input", tooltip_style)
    input_last_edit.pack(side='left')
    # ------------------------------------------------------------------------------
    input_cursor_position = Label(input_details_frame, text="1:1")
    input_cursor_position.pack(side='right')
    # ------------------------------------------------------------------------------
    input_details = Label(input_details_frame, text="Characters: 0", justify='center', anchor='center')
    input_details.pack(fill='x', side='left', expand=True)

    def Input_Details_Update():
        def index() -> str:
            try:
                ind = str(input.index('insert')).split(".")
                lines = ind[0]
                chars = ind[1]
                result = f"{lines}:{int(chars) + 1}"

                return result
            except Exception:
                return str(input.index('insert').replace('.', ':'))

        input_cursor_position.config(text=index())
        details = "Characters: %s" % (len(input.get(1.0, 'end').strip('\n')))
        input_details.config(text=details)
        input_last_edit.config(text=datetime.datetime.now().strftime("%Y/%m/%d - %I:%M:%S %p"))

    input.bind('<ButtonPress-1>', lambda a: Input_Details_Update())
    input.bind('<ButtonRelease-1>', lambda a: Input_Details_Update())
    input.bind('<KeyPress>', lambda a: Input_Details_Update())
    input.bind('<KeyRelease>', lambda a: Input_Details_Update())
    # ------------------------------------------------------------------------------
    input_actions_frame = Frame(input_frame)
    input_actions_frame.pack(side='bottom', fill='x')

    # ------------------------------------------------------------------------------
    def RedoInput():
        try:
            input.edit_redo()
            Input_Details_Update()
        except _tkinter.TclError:
            pass

    redo_input = Button(input_actions_frame, text="redo", bootstyle='secondary', cursor='hand2', takefocus=False,
                        command=lambda: RedoInput())
    redo_input.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def UndoInput():
        try:
            input.edit_undo()
            Input_Details_Update()
        except _tkinter.TclError:
            pass

    undo_input = Button(input_actions_frame, text="undo", bootstyle='secondary', cursor='hand2', takefocus=False,
                        command=lambda: UndoInput())
    undo_input.pack(side='left', fill='x', expand=True)
    # ------------------------------------------------------------------------------
    copy_input = Button(input_actions_frame, text="copy", bootstyle='secondary', cursor='hand2', takefocus=False,
                        command=lambda: pyperclip.copy(input.get(1.0, 'end').strip('\n')))
    copy_input.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def Paste_input():
        if pyperclip.paste():
            input.delete(1.0, 'end')
            input.insert(1.0, pyperclip.paste())
            Input_Details_Update()

    paste_input = Button(input_actions_frame, text="paste", bootstyle='secondary', cursor='hand2', takefocus=False,
                         command=lambda: Paste_input())
    paste_input.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def ClearInput():
        input.delete(1.0, 'end')
        Input_Details_Update()

    clear_input = Button(input_actions_frame, text="clear", bootstyle='secondary', cursor='hand2', takefocus=False,
                         command=lambda: ClearInput())
    clear_input.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def SaveInput2File():
        file = asksaveasfile(title="Save input to", defaultextension='txt', confirmoverwrite=True, mode='w',
                             initialfile=str(random.randint(1000000000, 9999999999)))
        if file:
            open(file.name, 'w').write(input.get(1.0, 'end').strip("\n"))

    save2file_input = Button(input_actions_frame, text="save", bootstyle='secondary', cursor='hand2', takefocus=False,
                             command=lambda: SaveInput2File())
    save2file_input.pack(side='left', fill='x', expand=True)
    ###############################################################################

    ###############################################################################
    output_frame = Frame(workspace_frame)
    output_frame.pack(fill='both', side='top', pady=5, expand=True)
    # ------------------------------------------------------------------------------
    output_text_frame = Frame(output_frame)
    output_text_frame.pack(side='top', fill='both', expand=True)
    # ------------------------------------------------------------------------------
    output_VScroll = Scrollbar(output_text_frame, orient="vertical", bootstyle="light-rounded")
    output_VScroll.pack(side='right', fill='y')
    # ------------------------------------------------------------------------------
    output = Text(output_text_frame, takefocus=True, maxundo=-1, undo=True, wrap="char",
                  yscrollcommand=output_VScroll.set)
    output.pack(fill='both', side='left', expand=True)
    output_VScroll.config(command=output.yview)
    # ------------------------------------------------------------------------------
    output_details_frame = Frame(output_frame)
    output_details_frame.pack(fill='x', side='bottom')
    # ------------------------------------------------------------------------------
    output_cursor_position = Label(output_details_frame, text="1:1")
    output_cursor_position.pack(side='right')
    # ------------------------------------------------------------------------------
    output_last_edit = Label(output_details_frame, text=datetime.datetime.now().strftime("%Y/%m/%d - %I:%M:%S %p"))
    ToolTip(output_last_edit, "Last interaction with output", tooltip_style)
    output_last_edit.pack(side='left')
    # ------------------------------------------------------------------------------
    output_details = Label(output_details_frame, text="Characters: 0", justify='center', anchor='center')
    output_details.pack(fill='x', side='left', expand=True)

    def Output_Details_Update():
        def index() -> str:
            try:
                ind = str(output.index('insert')).split(".")
                lines = ind[0]
                chars = ind[1]
                result = f"{lines}:{int(chars) + 1}"

                return result
            except Exception:
                return str(output.index('insert').replace('.', ':'))

        output_cursor_position.config(text=index())
        details = "Characters: %s" % (len(output.get(1.0, 'end').strip('\n')))
        output_details.config(text=details)
        output_last_edit.config(text=datetime.datetime.now().strftime("%Y/%m/%d - %I:%M:%S %p"))

    output.bind('<ButtonPress-1>', lambda a: Output_Details_Update())
    output.bind('<ButtonRelease-1>', lambda a: Output_Details_Update())
    output.bind('<KeyPress>', lambda a: Output_Details_Update())
    output.bind('<KeyRelease>', lambda a: Output_Details_Update())
    # ------------------------------------------------------------------------------
    output_actions_frame = Frame(output_frame)
    output_actions_frame.pack(side='bottom', fill='x')

    # ------------------------------------------------------------------------------
    def RedoOutput():
        try:
            output.edit_redo()
            Output_Details_Update()
        except _tkinter.TclError:
            pass

    redo_output = Button(output_actions_frame, text="redo", bootstyle='secondary', cursor='hand2', takefocus=False,
                         command=lambda: RedoOutput())
    redo_output.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def UndoOutput():
        try:
            output.edit_undo()
            Output_Details_Update()
        except _tkinter.TclError:
            pass

    undo_output = Button(output_actions_frame, text="undo", bootstyle='secondary', cursor='hand2', takefocus=False,
                         command=lambda: UndoOutput())
    undo_output.pack(side='left', fill='x', expand=True)
    # ------------------------------------------------------------------------------
    copy_output = Button(output_actions_frame, text="copy", bootstyle='secondary', cursor='hand2', takefocus=False,
                         command=lambda: pyperclip.copy(output.get(1.0, 'end').strip('\n')))
    copy_output.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def Paste_output():
        if pyperclip.paste():
            output.delete(1.0, 'end')
            output.insert(1.0, pyperclip.paste())
            Output_Details_Update()

    paste_output = Button(output_actions_frame, text="paste", bootstyle='secondary', cursor='hand2', takefocus=False,
                          command=lambda: Paste_output())
    paste_output.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def ClearOutput():
        output.delete(1.0, 'end')
        Output_Details_Update()

    clear_output = Button(output_actions_frame, text="clear", bootstyle='secondary', cursor='hand2', takefocus=False,
                          command=lambda: ClearOutput())
    clear_output.pack(side='left', fill='x', expand=True)

    # ------------------------------------------------------------------------------
    def SaveOutput2File():
        file = asksaveasfile(title="Save output to", defaultextension='txt', confirmoverwrite=True, mode='w',
                             initialfile=str(random.randint(1000000000, 9999999999)))
        if file:
            open(file.name, 'w').write(output.get(1.0, 'end').strip("\n"))

    save2file_output = Button(output_actions_frame, text="save", bootstyle='secondary', cursor='hand2', takefocus=False,
                              command=lambda: SaveOutput2File())
    save2file_output.pack(side='left', fill='x', expand=True)
    ###############################################################################
    execute = {
        'base16': {
            'safe': {"encode": lambda: Encode_base16(string=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Decode_base16(string=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Encode_base16(string=data)
        },
        'base32': {  # 'checksum': lambda data:
            'safe': {"encode": lambda: Encode_base32(string=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Decode_base32(string=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Encode_base32(string=data)
        },
        'base58': {
            'safe': {"encode": lambda: Encode_base58(string=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Decode_base58(string=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Encode_base58(string=data)
        },
        'base64': {
            'safe': {"encode": lambda: Encode_base64(string=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Decode_base64(string=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Encode_base64(string=data)
        },
        'base85': {
            'safe': {"encode": lambda: Encode_base85(string=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Decode_base85(string=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Encode_base85(string=data)
        },
        'base64.urlsafe': {
            'safe': {"encode": lambda: Encode_base64_urlsafe(string=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Decode_base64_urlsafe(string=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Encode_base64_urlsafe(string=data)
        },
        'binary': {
            'safe': {
                "encode": lambda: Binary_encrypt(text=input.get(1.0, 'end').strip('\n'),
                                                 separator=binary_separatorVar.get())},
            'unsafe': {
                "decode": lambda: Binary_decrypt(binary=input.get(1.0, 'end').strip('\n'),
                                                 separator=binary_separatorVar.get())},
            # 'checksum': lambda data:Binary_encrypt(text=data, separator=binary_separatorVar.get())
        },
        'morse': {
            'safe': {"encode": lambda: Morse_encode(text=input.get(1.0, 'end').strip('\n'),
                                                    seperator=morse_separatorVar.get(), dot=morse_dotsVar.get(),
                                                    dash=morse_dashesVar.get())},
            'unsafe': {"decode": lambda: Morse_decode(morse=input.get(1.0, 'end').strip('\n'),
                                                      seperator=morse_separatorVar.get(), dot=morse_dotsVar.get(),
                                                      dash=morse_dashesVar.get())},
            # 'checksum': lambda data:Morse_encrypt(text=data)
        },
        'braille': {
            'safe': {"encode": lambda: Braille.encode(text=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Braille.decode(braille=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Morse_encrypt(text=data)
        },
        'url': {
            'safe': {"encode": lambda: Url.encode(url=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Url.decode(url=input.get(1.0, 'end').strip('\n'))},
            # 'checksum': lambda data:Morse_encrypt(text=data)
        },
        'rot13': {
            'safe': {"encode": lambda: Caesar_encode(string=input.get(1.0, 'end').strip('\n'), shift=13)},
            'unsafe': {"decode": lambda: Caesar_decode(string=input.get(1.0, 'end').strip('\n'), shift=13)},
            # 'checksum': lambda data:Caesar_encode(string=data, shift=13)
        },
        'caesar': {
            'safe': {"encode": lambda: Caesar_encode(string=input.get(1.0, 'end').strip('\n'),
                                                     shift=caesar_shiftsVar.get())},
            'unsafe': {"decode": lambda: Caesar_decode(string=input.get(1.0, 'end').strip('\n'),
                                                       shift=caesar_shiftsVar.get())},
            # 'checksum': lambda data:Caesar_encode(string=data, shift=caesar_shiftsVar.get())
        },
        'hexdump': {
            'safe': {"dump": lambda: HexDump(file=hexdump_file.get(), fence=hexdump_fenceVar.get(),
                                             type=hexdump_typeVar.get())},
            # 'unsafe': lambda: HexDump(file=hexdump_file.get(), fence=hexdump_fenceVar.get(), type=hexdump_typeVar.get())
        },
        'dummy': {
            'safe': {
                "encode": lambda: Encode_dummy(string=input.get(1.0, 'end').strip('\n'),
                                               seperator=dummy_separatorVar.get(),
                                               is_english_letters_upper=Dummy_en_letters_upperVar.get(),
                                               is_english_letters_lower=Dummy_en_letters_lowerVar.get(),
                                               is_global_punctuations=Dummy_global_punctuationsVar.get(),
                                               is_arabic_letters=Dummy_ar_lettersVar.get(),
                                               is_arabic_numbers=Dummy_ar_numbersVar.get(),
                                               is_arabic_punctuations=Dummy_ar_punctuationsVar.get(),
                                               is_arabic_formatters=Dummy_ar_formattersVar.get())},
            'unsafe': {
                "decode": lambda: Decode_dummy(string=input.get(1.0, 'end').strip('\n'),
                                               seperator=dummy_separatorVar.get(),
                                               is_english_letters_upper=Dummy_en_letters_upperVar.get(),
                                               is_english_letters_lower=Dummy_en_letters_lowerVar.get(),
                                               is_global_punctuations=Dummy_global_punctuationsVar.get(),
                                               is_arabic_letters=Dummy_ar_lettersVar.get(),
                                               is_arabic_numbers=Dummy_ar_numbersVar.get(),
                                               is_arabic_punctuations=Dummy_ar_punctuationsVar.get(),
                                               is_arabic_formatters=Dummy_ar_formattersVar.get())},
            # 'checksum': lambda data:Encode_dummy(string=data, seperator=dummy_separatorVar.get())
        },
        'md2': {
            'safe': {
                "hash": lambda: _Md2_(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: _Md2_(string=data, type=hashing_typeVar.get())}
        },
        'md4': {
            'safe': {
                "hash": lambda: _Md4_(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: _Md4_(string=data, type=hashing_typeVar.get())}
        },
        'md5': {
            'safe': {
                "hash": lambda: Md5(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Md5(string=data, type=hashing_typeVar.get())}
        },
        'sha1': {
            'safe': {
                "hash": lambda: Sha1(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha1(string=data, type=hashing_typeVar.get())}
        },
        'sha224': {
            'safe': {
                "hash": lambda: Sha224(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha224(string=data, type=hashing_typeVar.get())}
        },
        'sha256': {
            'safe': {
                "hash": lambda: Sha256(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha256(string=data, type=hashing_typeVar.get())}
        },
        'sha384': {
            'safe': {
                "hash": lambda: Sha384(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha384(string=data, type=hashing_typeVar.get())}
        },
        'sha512': {
            'safe': {
                "hash": lambda: Sha512(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha512(string=data, type=hashing_typeVar.get())}
        },
        'sha3.224': {
            'safe': {"hash": lambda: Sha3_224(string=input.get(1.0, 'end').strip('\n').encode(),
                                              type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha3_224(string=data, type=hashing_typeVar.get())}
        },
        'sha3.256': {
            'safe': {"hash": lambda: Sha3_256(string=input.get(1.0, 'end').strip('\n').encode(),
                                              type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha3_256(string=data, type=hashing_typeVar.get())}
        },
        'sha3.384': {
            'safe': {"hash": lambda: Sha3_384(string=input.get(1.0, 'end').strip('\n').encode(),
                                              type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha3_384(string=data, type=hashing_typeVar.get())}
        },
        'sha3.512': {
            'safe': {"hash": lambda: Sha3_512(string=input.get(1.0, 'end').strip('\n').encode(),
                                              type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Sha3_512(string=data, type=hashing_typeVar.get())}
        },
        'shake128': {
            'safe': {
                "hash": lambda: Shake128(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get(),
                                         length=shake_lengthVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Shake128(string=data, type=hashing_typeVar.get(),
                                                           length=shake_lengthVar.get())}
        },
        'shake256': {
            'safe': {
                "hash": lambda: Shake256(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get(),
                                         length=shake_lengthVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Shake256(string=data, type=hashing_typeVar.get(),
                                                           length=shake_lengthVar.get())}
        },
        'blake2s': {
            'safe': {"hash": lambda: Black2s(string=input.get(1.0, 'end').strip('\n'), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Black2s(string=data, type=hashing_typeVar.get())}
        },
        'blake2b': {
            'safe': {"hash": lambda: Black2b(string=input.get(1.0, 'end').strip('\n'), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Black2b(string=data, type=hashing_typeVar.get())}
        },
        'adler32': {
            'safe': {"hash": lambda: Adler_32(string=input.get(1.0, 'end').strip('\n').encode())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Adler_32(string=data)}
        },
        'ripemd160': {
            'safe': {"hash": lambda: Ripemd_160(string=input.get(1.0, 'end').strip('\n').encode(),
                                                type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Ripemd_160(string=data, type=hashing_typeVar.get())}
        },
        'keccak224': {
            'safe': {"hash": lambda: Keccak224(string=input.get(1.0, 'end').strip('\n').encode(),
                                               type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Keccak224(string=data, type=hashing_typeVar.get())}
        },
        'keccak256': {
            'safe': {"hash": lambda: Keccak256(string=input.get(1.0, 'end').strip('\n').encode(),
                                               type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Keccak256(string=data, type=hashing_typeVar.get())}
        },
        'keccak384': {
            'safe': {"hash": lambda: Keccak384(string=input.get(1.0, 'end').strip('\n').encode(),
                                               type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Keccak384(string=data, type=hashing_typeVar.get())}
        },
        'keccak512': {
            'safe': {"hash": lambda: Keccak512(string=input.get(1.0, 'end').strip('\n').encode(),
                                               type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Keccak512(string=data, type=hashing_typeVar.get())}
        },
        'crc8': {
            'safe': {
                "hash": lambda: _Crc8_(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: _Crc8_(string=data, type=hashing_typeVar.get())}
        },
        'crc16': {
            'safe': {"hash": lambda: _Crc16_(string=input.get(1.0, 'end').strip('\n').encode())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: _Crc16_(string=data)}
        },
        'crc32': {
            'safe': {"hash": lambda: _Crc32_(string=input.get(1.0, 'end').strip('\n').encode())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: _Crc32_(string=data)}
        },
        'ntlm': {
            'safe': {"hash": lambda: Ntlm(string=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :None,
            # 'checksum': lambda data: Ntlm(string=data)
        },
        'cmac': {
            'safe': {
                "hash": lambda: Cmac(key=cmac_key.get().encode(), string=input.get(1.0, 'end').strip('\n').encode(),
                                     type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {
                "checksum": lambda data: Cmac(string=data, key=cmac_key.get().encode(), type=hashing_typeVar.get())}
        },
        'kmac128': {
            'safe': {"hash": lambda: _KMAC128_(key=cmac_key.get(), data=input.get(1.0, 'end').strip('\n'),
                                               type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: _KMAC128_(data=data, key=cmac_key.get(), type=hashing_typeVar.get())}
        },
        'kmac256': {
            'safe': {"hash": lambda: _KMAC256_(key=cmac_key.get(), data=input.get(1.0, 'end').strip('\n'),
                                               type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: _KMAC256_(data=data, key=cmac_key.get(), type=hashing_typeVar.get())}
        },
        'hmac': {
            'safe': {"hash": lambda: Hmac(key=hmac_key.get(), msg=input.get(1.0, 'end').strip('\n'),
                                          digestmod=hmac_digestmodVar.get(), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Hmac(key=hmac_key.get(), msg=data, digestmod=hmac_digestmodVar.get(),
                                                       type=hashing_typeVar.get())}
        },
        'bcrypt': {
            'safe': {"encrypt": lambda: Bcrypt_Encryption(string=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :Bcrypt_Decryption(hashed_password=input.get(1.0, 'end').strip('\n'), password=bcrypt_salt.get()),
            # 'checksum': lambda data: Bcrypt_Encryption(string=data)
        },
        'poly1305': {
            'safe': {"hash": lambda: _Poly1305_(key=poly1305_key.get(), string=input.get(1.0, 'end').strip('\n'),
                                                type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {
                "checksum": lambda data: _Poly1305_(key=poly1305_key.get(), string=data, type=hashing_typeVar.get())}
        },
        'whirlpool': {
            'safe': {"hash": lambda: Whirlpool(string=input.get(1.0, 'end').strip('\n'), type=hashing_typeVar.get())},
            # 'unsafe': lambda :None,
            'checksum': {"checksum": lambda data: Whirlpool(string=data, type=hashing_typeVar.get())}
        },
        'aes128': {
            'safe': {"encrypt": lambda: AES128_Encryption(data=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {
                "decrypt": lambda: AES128_Decryption(data=input.get(1.0, 'end').strip('\n'), key=aes128_key.get())},
            'checksum': {"checksum": lambda data: AES128_Encryption(data=data)}
        },
        'punycode': {
            'safe': {"encode": lambda: Punycode.encode(domain=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Punycode.decode(domain=input.get(1.0, 'end').strip('\n').encode())}
        },
        'hexadecimal': {
            'safe': {"encode": lambda: Encode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))},
            'unsafe': {"decode": lambda: Decode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))}
        },
        'color to rgb': {
            'safe': {"convert": lambda: Color2RGB(color=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :Decode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))
        },
        'color to hex': {
            'safe': {"convert": lambda: Color2Hex(color=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :Decode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))
        },
        'hex to color': {
            'safe': {"convert": lambda: Hex2Color(hex=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :Decode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))
        },
        'hex to rgb': {
            'safe': {"convert": lambda: Hex2RGB(hex=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :Decode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))
        },
        'rgb to hex': {
            'safe': {"convert": lambda: RGB2Hex(rgb=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :Decode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))
        },
        'rgb to color': {
            'safe': {"convert": lambda: RGB2Color(rgb=input.get(1.0, 'end').strip('\n'))},
            # 'unsafe': lambda :Decode_Hexadecimal(data=input.get(1.0, 'end').strip('\n'))
        },
        'html': {
            'safe': {
                "encode": lambda: HTML_encode(string=input.get(1.0, 'end').strip('\n'), quote=HTML_quoteVar.get())},
            'unsafe': {"decode": lambda: HTML_decode(string=input.get(1.0, 'end').strip('\n'))}
        },
        'timestamp': {
            'safe': {
                "timestamp": lambda: Date2Timestamp(year=timestamp_yearVar.get(), month=timestamp_month_numberVar.get(),
                                                    day=timestamp_dayVar.get(), hour=timestamp_hourVar.get(),
                                                    minute=timestamp_minuteVar.get(),
                                                    second=timestamp_secondVar.get())},
            'unsafe': {"date": lambda: Timestamp2Date(timestamp=input.get(1.0, 'end').strip("\n"))}
        },
        'zlib': {
            'safe': {"compress": lambda: Zlib_compress(data=input.get(1.0, 'end').strip('\n'),
                                                       level=zlib_comp_levelVar.get())},
            # 'unsafe': lambda: Timestamp2Date(timestamp=input.get(1.0, 'end').strip("\n"))
        },
        'replace': {
            'safe': {"replace": lambda: re.sub(pattern=replace_from.get(), string=input.get(1.0, 'end').strip('\n'),
                                               repl=replace_to.get())},
            # 'unsafe': lambda: Timestamp2Date(timestamp=input.get(1.0, 'end').strip("\n"))
        },
        'remove': {
            'safe': {"remove": lambda: re.sub(pattern=remove_character.get(), string=input.get(1.0, 'end').strip('\n'),
                                              repl="")},
            # 'unsafe': lambda: Timestamp2Date(timestamp=input.get(1.0, 'end').strip("\n"))
        }
        # 'magic': {}, # detect hashing/encoding/encryption modules.
    }

    Frame(types_frame).pack(side='right', fill='y', padx=5)
    types_radiobtns_frame = Frame(types_frame)
    types_radiobtns_frame.pack(side='left', fill='both', expand=True)
    selected_typeVar = StringVar()

    def Type_changed():
        try:
            module = selected_typeVar.get()
            type_safe_name = list(execute[module].keys())
            # ==============================================================================================================
            if 'safe' in type_safe_name:
                safe_name = list(execute[module]['safe'].keys())[0]
                Safe.config(text=safe_name.capitalize(), command=lambda: Run(method="safe", action=safe_name))
                Safe.pack(side='left', fill='x', expand=True)
            else:
                Safe.pack_forget()
            # ==============================================================================================================
            if 'unsafe' in type_safe_name:
                unsafe_name = list(execute[module]['unsafe'].keys())[0]
                UnSafe.config(text=unsafe_name.capitalize(), command=lambda: Run(method="unsafe", action=unsafe_name))
                UnSafe.pack(side='right', fill='x', expand=True)
            else:
                UnSafe.pack_forget()
            # ==============================================================================================================
            if 'checksum' in type_safe_name:
                checksum_name = list(execute[module]['checksum'].keys())[0]
                Checksum.config(text=checksum_name.capitalize(),
                                command=lambda: Run(method="checksum", action=checksum_name))
                Checksum.pack(side='left', fill='x', expand=True)
            else:
                Checksum.pack_forget()
            # ==============================================================================================================
            type_lbl.config(text='~ ' + module.upper() + ' ~')
        except Exception:
            type_lbl.config(text="Welcome back!")
            Safe.pack(side='left', fill='x', expand=True)
            UnSafe.pack(side='right', fill='x', expand=True)
            Checksum.pack(side='left', fill='x', expand=True)

    for i in sorted(list(execute.keys())):
        Radiobutton(types_radiobtns_frame, text=i.upper(), value=i, variable=selected_typeVar,
                    bootstyle='toolbutton-dark', padding=15, takefocus=False, cursor='hand2',
                    command=lambda: Type_changed()).pack(fill='x', pady=1)

    def Run(method: str, action: str):  # method= safe/unsafe [checksum]
        methods = ["safe", "unsafe"]  # + ["checksum"]
        if selected_typeVar.get():
            module = selected_typeVar.get()
            if method in execute[module]:
                if method in methods:
                    try:
                        _out_ = execute[module][method][action]()
                        output.delete(1.0, 'end')
                        output.insert(1.0, _out_)

                        Output_Details_Update()
                        Input_Details_Update()
                    except _tkinter.TclError:
                        pass
                elif method == "checksum":
                    file = askopenfilename(title="what file?")
                    if file:
                        try:
                            _out_ = execute[module][method][action](open(file=file, mode="rb").read())
                            input.delete(1.0, 'end')
                            input.insert(1.0, file)

                            output.delete(1.0, 'end')
                            output.insert(1.0, _out_)

                            Output_Details_Update()
                            Input_Details_Update()
                        except _tkinter.TclError:
                            pass

    ####################################################################
    WorkSpace_actions_Frame = Frame(workspace_frame)  # SU=Safe/Unsafe
    WorkSpace_actions_Frame.pack(side='bottom', fill='x')
    # -------------------------------------------------------------------
    Top_WorkSpace_actions_Frame = Frame(WorkSpace_actions_Frame)  # SU=Safe/Unsafe
    Top_WorkSpace_actions_Frame.pack(side='top', fill='x')
    # -------------------------------------------------------------------
    Bottom_WorkSpace_actions_Frame = Frame(WorkSpace_actions_Frame)  # SU=Safe/Unsafe
    Bottom_WorkSpace_actions_Frame.pack(side='bottom', fill='x')

    # -------------------------------------------------------------------
    def Output2Input():
        if output.get(1.0, 'end').strip('\n'):
            input.delete(1.0, 'end')
            input.insert(1.0, output.get(1.0, 'end').strip('\n'))

            Output_Details_Update()
            Input_Details_Update()

    move_output2input = Button(Bottom_WorkSpace_actions_Frame, text="▲", padding=10, bootstyle='secondary',
                               cursor='hand2',
                               takefocus=False, command=lambda: Output2Input())
    move_output2input.pack(side='left', fill='x', expand=True)
    # -------------------------------------------------------------------
    Safe = Button(Top_WorkSpace_actions_Frame, text="Safe", bootstyle="success", padding=10, cursor='hand2',
                  takefocus=False)
    Safe.pack(side='left', fill='x', expand=True)

    # -------------------------------------------------------------------
    def FieldsSwap():
        inp = input.get(1.0, 'end').strip('\n')
        out = output.get(1.0, 'end').strip('\n')
        input.delete(1.0, 'end')
        output.delete(1.0, 'end')
        input.insert(1.0, out)
        output.insert(1.0, inp)

        Output_Details_Update()
        Input_Details_Update()

    output_switch = Button(Bottom_WorkSpace_actions_Frame, text="▲▼", padding=10, bootstyle='secondary', cursor='hand2',
                           takefocus=False, command=lambda: FieldsSwap())
    output_switch.pack(side='left', fill='x', expand=True, padx=1)

    # -------------------------------------------------------------------
    def Input2Output():
        if input.get(1.0, 'end').strip('\n'):
            output.delete(1.0, 'end')
            output.insert(1.0, input.get(1.0, 'end').strip('\n'))
            Output_Details_Update()
            Input_Details_Update()

    move_input2output = Button(Bottom_WorkSpace_actions_Frame, text="▼", padding=10, bootstyle='secondary',
                               cursor='hand2',
                               takefocus=False, command=lambda: Input2Output())
    move_input2output.pack(side='right', fill='x', expand=True)
    # -------------------------------------------------------------------
    UnSafe = Button(Top_WorkSpace_actions_Frame, text="Unsafe", bootstyle="danger", padding=10, cursor='hand2')
    UnSafe.pack(side='right', fill='x', expand=True)
    # -------------------------------------------------------------------
    Checksum = Button(Top_WorkSpace_actions_Frame, text="Checksum", bootstyle="primary", padding=10, cursor='hand2',
                      takefocus=False)
    Checksum.pack(side='left', fill='x', expand=True)
    ####################################################################

    ################################################
    # Action_menu.add_command(label="Safe", command=lambda: Run(method="safe"))
    # Action_menu.add_command(label="Unsafe", command=lambda: Run(method="unsafe"))
    # Action_menu.add_command(label="Checksum", command=lambda: Run(method="checksum"))
    ################################################
    Edit_Data_menu = Menu()
    Edit_menu.add_cascade(label="Data", menu=Edit_Data_menu)
    Edit_Data_menu.add_command(label="Swap input & output", command=lambda: FieldsSwap())
    # ----------------------------------------------
    Edit_Data_Input_menu = Menu()
    Edit_Data_menu.add_cascade(label="Input", menu=Edit_Data_Input_menu)
    Edit_Data_Input_menu.add_command(label="Redo", command=lambda: RedoInput())
    Edit_Data_Input_menu.add_command(label="Undo", command=lambda: UndoInput())
    Edit_Data_Input_menu.add_command(label="Copy", command=lambda: pyperclip.copy(input.get(1.0, 'end').strip('\n')))
    Edit_Data_Input_menu.add_command(label="Paste", command=lambda: Paste_input())
    Edit_Data_Input_menu.add_command(label="Clear", command=lambda: ClearInput())
    Edit_Data_Input_menu.add_command(label="Save", command=lambda: SaveInput2File())
    Edit_Data_Input_menu.add_command(label="Move to output", command=lambda: Input2Output())
    # ----------------------------------------------
    Edit_Data_Output_menu = Menu()
    Edit_Data_menu.add_cascade(label="Output", menu=Edit_Data_Output_menu)
    Edit_Data_Output_menu.add_command(label="Redo", command=lambda: RedoOutput())
    Edit_Data_Output_menu.add_command(label="Undo", command=lambda: UndoOutput())
    Edit_Data_Output_menu.add_command(label="Copy", command=lambda: pyperclip.copy(output.get(1.0, 'end').strip('\n')))
    Edit_Data_Output_menu.add_command(label="Paste", command=lambda: Paste_output())
    Edit_Data_Output_menu.add_command(label="Clear", command=lambda: ClearOutput())
    Edit_Data_Output_menu.add_command(label="Save", command=lambda: SaveOutput2File())
    Edit_Data_Output_menu.add_command(label="Move to Input", command=lambda: Input2Output())
    ################################################

    h3x0r.config(menu=menubar)
    h3x0r.mainloop()


Hexor()
