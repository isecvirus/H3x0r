#!/usr/bin/env python3
import datetime
import os
import platform
import random
import string
from tkinter import StringVar, Text, PhotoImage, IntVar, Menu
from tkinter.filedialog import asksaveasfile, askopenfilename
from tkinter.messagebox import askokcancel
import _tkinter
import pyperclip
import requests
from ttkbootstrap.tooltip import ToolTip
from ttkbootstrap.toast import ToastNotification
from ttkbootstrap import Window, Toplevel
from ttkbootstrap.scrolled import ScrolledFrame
from tkinter.ttk import *
from hAdler32 import Adler_32
from hBcrypt import Bcrypt_Encryption
from hCmac import Cmac
from hCrc16 import _Crc16_
from hCrc32 import _Crc32_
from hCrc8 import _Crc8_
from hKeccak224 import Keccak224
from hKeccak256 import Keccak256
from hKeccak384 import Keccak384
from hKeccak512 import Keccak512
from hNtlm import Ntlm
from hPunycode import Punycode
from hRipemd160 import Ripemd_160
from utils import monitor
from logo import png256x256
from hMorse import Morse_encrypt, Morse_decrypt
from Binary import Binary_encrypt, Binary_decrypt
from hBase16 import Encode_base16, Decode_base16
from hBase32 import Encode_base32, Decode_base32
from hBase58 import Encode_base58, Decode_base58
from hBase64 import Encode_base64, Decode_base64
from hBase85 import Encode_base85, Decode_base85
from hBase64_urlsafe import Encode_base64_urlsafe, Decode_base64_urlsafe
from hCaesar import Caesar_encode, Caesar_decode
from hHexdump import HexDump
from hDummy import Encode_dummy, Decode_dummy
from hMd2 import _Md2_
from hMd4 import _Md4_
from hMd5 import Md5
from hSha1 import Sha1
from hSha224 import Sha224
from hSha256 import Sha256
from hSha384 import Sha384
from hSha512 import Sha512
from hSha3_224 import Sha3_224
from hSha3_256 import Sha3_256
from hSha3_384 import Sha3_384
from hSha3_512 import Sha3_512
from hShake128 import Shake128
from hShake256 import Shake256
from hBlack2s import Black2s
from hBlack2b import Black2b
from hHmac import Hmac
from hPoly1305 import _Poly1305_
from hWhirlpool import Whirlpool
from hAES128 import AES128_Encryption, AES128_Decryption
from hBraille import Braille
from hUrl import Url

def Hexor():
    window = Window(themename='darkly')  # yeti, darkly
    width = monitor(window)['width']
    height = monitor(window)['height']
    window.geometry(f"{width // 2}x{int(height // 1.25)}+{int(width // 3.75)}+{height // 12}")
    icon = PhotoImage(data=png256x256)
    window.call('wm', 'iconphoto', window._w, icon)
    window.title("H3x0r")

    if "windows" in platform.platform().lower(): window.state("zoom")

    tooltip_style = "secondary.inverse"

    ###############################################
    menubar = Menu()
    ###############################################

    ###############################################
    Edit_menu = Menu()
    menubar.add_cascade(label="Edit", menu=Edit_menu)
    ###############################################

    ###############################################
    Action_menu = Menu()
    menubar.add_cascade(label="Action", menu=Action_menu)
    ###############################################

    ###############################################
    Compare_menubar = Menu()
    menubar.add_cascade(label="Compare", menu=Compare_menubar)
    def Compare_checksum(type:str):
        file1 = askopenfilename(title=f"File 1 ({type.upper().replace('.', ' ')})")
        if file1:
            file2 = askopenfilename(title=f"File 2 ({type.upper().replace('.', ' ')})")
            if file2:
                start = datetime.datetime.now()
                hash1 = execute[type]["checksum"](open(file=file1, mode="rb").read())
                hash2 = execute[type]["checksum"](open(file=file2, mode="rb").read())
                end = str(datetime.datetime.now() - start)

                if hash1 == hash2:
                    ToastNotification(title=f"{type.upper().replace('.', ' ')}", message=f"file1: {file1}\nfile2: {file2}\nhash: {hash1}\nestimated: {end[:-4]}", bootstyle="success", icon="✅", duration=0).show_toast()
                else:
                    ToastNotification(title=f"{type.upper().replace('.', ' ')}", message=f"file1: {file1}\nfile2: {file2}\nhash1: {hash1}\nhash2: {hash2}\nestimated: {end[:-4]}", bootstyle="danger", icon="❌", duration=0).show_toast()
    Compare_menubar.add_command(label="MD2", command=lambda :Compare_checksum(type="md2"))
    Compare_menubar.add_command(label="MD4", command=lambda :Compare_checksum(type="md4"))
    Compare_menubar.add_command(label="MD5", command=lambda :Compare_checksum(type="md5"))
    Compare_menubar.add_command(label="Sha1", command=lambda :Compare_checksum(type="sha1"))
    Compare_menubar.add_command(label="Sha224", command=lambda :Compare_checksum(type="sha224"))
    Compare_menubar.add_command(label="Sha256", command=lambda :Compare_checksum(type="sha256"))
    Compare_menubar.add_command(label="Sha384", command=lambda :Compare_checksum(type="sha384"))
    Compare_menubar.add_command(label="Sha512", command=lambda :Compare_checksum(type="sha512"))
    Compare_menubar.add_command(label="Sha3-224", command=lambda :Compare_checksum(type="sha3.224"))
    Compare_menubar.add_command(label="Sha3-256", command=lambda :Compare_checksum(type="sha3.256"))
    Compare_menubar.add_command(label="Sha3-384", command=lambda :Compare_checksum(type="sha3.384"))
    Compare_menubar.add_command(label="Sha3-512", command=lambda :Compare_checksum(type="sha3.512"))
    Compare_menubar.add_command(label="SHAKE128", command=lambda :Compare_checksum(type="shake.128"))
    Compare_menubar.add_command(label="SHAKE256", command=lambda :Compare_checksum(type="shake.256"))
    #----------------------------------------------
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
    Insert_menu.add_command(label="File", command=lambda :InsertFromFile())
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
        confirm = Button(topwin, text="Confirm", cursor="hand2", takefocus=False, command=lambda :Confirm())
        confirm.pack(side='bottom', fill='x', expand=True)
        topwin.mainloop()
    Insert_menu.add_command(label="Url", command=lambda :InsertFromUrl())
    #----------------------------------------------
    def Exit():
        if askokcancel(title="Are you sure?", message="Nothing will be saved."):
            window.destroy()
    menubar.add_command(label="Exit", command=lambda :Exit())
    ###############################################

    right_frame = Frame(window, width=width // 6)
    right_frame.pack(side='right', fill='both')
    left_frame = Frame(window, width=width // 6)
    left_frame.pack(side='left', fill='both')

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
    #----------->                                       <-----------#
    #--------->                 STAGER                    <---------#
    #----------->                                       <-----------#
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!#
    # stager_frame = ScrolledFrame(left_frame, bootstyle='secondary', height=height)
    # stager_frame.vscroll.config(bootstyle='light-rounded')
    # stager_frame.pack(fill='both', side='right', expand=True)
    # stages_list = Listbox(stager_frame, font=("' 15"), justify='center', selectmode='single')
    # for i in range(100):stages_list.insert('end', str(random.randint(1111111111,99999999999999999)))
    # stages_list.pack(fill='both', expand=True)
    #################################################################

    settings_frame = ScrolledFrame(left_frame, bootstyle='secondary', height=height, cursor='sb_v_double_arrow')
    # settings_frame.vscroll.config(bootstyle='light-rounded')
    # settings_frame.vscroll.pack(side='left')
    settings_frame.vscroll.pack_forget()
    settings_frame.pack(fill='both', side='left')

    ###########################################################################
    binary_settings_frame = LabelFrame(settings_frame, text="Binary")
    binary_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(binary_settings_frame, text="Separator").pack()
    binary_separators = (" ",) + tuple(string.punctuation)
    binary_separatorVar = StringVar(value=" ")
    binary_separator_combobox = Combobox(binary_settings_frame, state='readonly', textvariable=binary_separatorVar, values=binary_separators, bootstyle='info')
    ToolTip(binary_separator_combobox, "Binary separator", tooltip_style, alpha=1)
    binary_separator_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    caesar_settings_frame = LabelFrame(settings_frame, text="Caesar")
    caesar_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(caesar_settings_frame, text="Shifts").pack()
    caesar_shiftsVar = IntVar(value=3)
    caesar_separator_spinbox = Spinbox(caesar_settings_frame, state='readonly', textvariable=caesar_shiftsVar, takefocus=False, wrap=False, from_=1, to=1000, bootstyle='info')
    ToolTip(binary_separator_combobox, "Caesar shift times", tooltip_style, alpha=1)
    caesar_separator_spinbox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    hexdump_settings_frame = LabelFrame(settings_frame, text="Hexdump")
    hexdump_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(hexdump_settings_frame, text="File").pack()
    hexdump_file_frame = Frame(hexdump_settings_frame)
    hexdump_file_frame.pack(side='top', fill='both', padx=10)
    hexdump_file = Entry(hexdump_file_frame, bootstyle='info')
    ToolTip(hexdump_file, "Hexdump file to dump", tooltip_style, alpha=1)
    hexdump_file.pack(side='left', fill='both', expand=True)
    def HexdumpFilePick():
        file = askopenfilename(title="what file?")
        if file:
            hexdump_file.delete(1, 'end')
            hexdump_file.insert(1, file)
    hexdump_file_pick = Button(hexdump_file_frame, text="..", cursor='hand2', takefocus=False, bootstyle='info', command=lambda :HexdumpFilePick())
    hexdump_file_pick.pack(side='right', fill='both', padx=3)
    #--------------------------------------------------------------------------
    Label(hexdump_settings_frame, text="Type").pack()
    hexdump_types = ("hexadecimal", "binary")
    hexdump_typeVar = StringVar(value=hexdump_types[0])
    hexdump_type_combobox = Combobox(hexdump_settings_frame, state='readonly', textvariable=hexdump_typeVar, values=hexdump_types, bootstyle='info')
    ToolTip(hexdump_type_combobox, "Hexdump as hexadecimal or binary", tooltip_style, alpha=1)
    hexdump_type_combobox.pack(side='top', fill='both', padx=10)
    #--------------------------------------------------------------------------
    Label(hexdump_settings_frame, text="Fence").pack()
    hexdump_separators = (" ",) + tuple(string.punctuation)
    hexdump_fenceVar = StringVar(value="|")
    hexdump_separator_combobox = Combobox(hexdump_settings_frame, state='readonly', textvariable=hexdump_fenceVar, values=hexdump_separators, bootstyle='info')
    ToolTip(hexdump_separator_combobox, "Hexdump data fence", tooltip_style, alpha=1)
    hexdump_separator_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    dummy_settings_frame = LabelFrame(settings_frame, text="Dummy")
    dummy_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(dummy_settings_frame, text="Seperator").pack()
    dummy_separators = (" ",) + tuple(string.punctuation)
    dummy_separatorVar = StringVar(value=".")
    dummy_separator_combobox = Combobox(dummy_settings_frame, state='readonly', textvariable=dummy_separatorVar, values=dummy_separators, bootstyle='info')
    ToolTip(dummy_separator_combobox, "Dummy data seperator", tooltip_style, alpha=1)
    dummy_separator_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    cmac_settings_frame = LabelFrame(settings_frame, text="CMAC")
    cmac_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(cmac_settings_frame, text="Key").pack()
    cmac_key = Entry(cmac_settings_frame, bootstyle='info')
    ToolTip(cmac_key, "CMAC key (password?!) length must be 16", tooltip_style, alpha=1)
    cmac_key.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    hmac_settings_frame = LabelFrame(settings_frame, text="HMAC")
    hmac_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(hmac_settings_frame, text="Key").pack()
    hmac_key = Entry(hmac_settings_frame, bootstyle='info')
    ToolTip(hmac_key, "HMAC key (password?!)", tooltip_style, alpha=1)
    hmac_key.pack(side='top', fill='both', padx=10)
    #--------------------------------------------------------------------------
    Label(hmac_settings_frame, text="Digest mode").pack()
    hmac_digestmods = ['md5-sha1', 'whirlpool', 'sm3', 'sha512-224', 'mdc2', 'ripemd160', 'md4', 'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3_224', 'sha3_256', 'sha3_384', 'sha3_512', 'blake2b']
    hmac_digestmodVar = StringVar(value=sorted(hmac_digestmods)[0])
    hmac_digestmod = Combobox(hmac_settings_frame, state='readonly', textvariable=hmac_digestmodVar, values=sorted(hmac_digestmods), bootstyle='info')
    ToolTip(hmac_digestmod, "HMAC digest mode", tooltip_style, alpha=1)
    hmac_digestmod.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    poly1305_settings_frame = LabelFrame(settings_frame, text="Poly1305")
    poly1305_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(poly1305_settings_frame, text="Key").pack()
    poly1305_key = Entry(poly1305_settings_frame, bootstyle='info')
    ToolTip(poly1305_key, "Poly1305 key", tooltip_style, alpha=1)
    poly1305_key.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    shake_settings_frame = LabelFrame(settings_frame, text="Shake128/256")
    shake_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(shake_settings_frame, text="Length").pack()
    shake_lengthVar = IntVar(value=1)
    shake_length = Spinbox(shake_settings_frame, from_=1, to=1000, textvariable=shake_lengthVar, state="readonly", increment=1, bootstyle='info')
    ToolTip(shake_length, "Shake128/256 length", tooltip_style, alpha=1)
    shake_length.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    aes128_settings_frame = LabelFrame(settings_frame, text="AES128")
    aes128_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(aes128_settings_frame, text="Key").pack()
    aes128_key = Entry(aes128_settings_frame, bootstyle='info')
    ToolTip(aes128_key, "Aes128 key", tooltip_style, alpha=1)
    aes128_key.pack(side='top', fill='both', padx=10)
    ###########################################################################

    ###########################################################################
    hashing_settings_frame = LabelFrame(settings_frame, text="Hashing type")
    hashing_settings_frame.pack(side='top', fill='both', ipadx=5, ipady=5)
    #--------------------------------------------------------------------------
    Label(hashing_settings_frame, text="Type").pack()
    hashing_types = ("hexdigest", "digest")
    hashing_typeVar = StringVar(value="hexdigest")
    hasing_type_combobox = Combobox(hashing_settings_frame, state='readonly', textvariable=hashing_typeVar, values=hashing_types, bootstyle='info')
    ToolTip(hasing_type_combobox, "hashing type of:\n\nSHA1\nSHA224\nSHA256\nSHA384\nSHA512\nSHA3_224\nSHA3_256\nSHA3_384\nSHA3_512\nSHAKE128\nSHAKE256\nBLACK2S\nBLACK2B\nRIPEMD160\nKECCAK224\nKECCAK256\nKECCAK384\nKECCAK512\nCRC8\nPOLY1305.", tooltip_style, alpha=1)
    hasing_type_combobox.pack(side='top', fill='both', padx=10)
    ###########################################################################

    icon = PhotoImage(data=png256x256)
    Label(right_frame, bootstyle="danger", justify='center', anchor='center', image=icon).pack(fill='x', ipady=10)

    types_frame = ScrolledFrame(right_frame, bootstyle='secondary', height=height)
    types_frame.vscroll.config(bootstyle='light-rounded')
    types_frame.pack(fill='both')

    workspace_frame = Frame(window, bootstyle='dark')
    workspace_frame.pack(fill='both', expand=True)

    type_lbl = Label(workspace_frame, text="Welcome back!", font=("' 25"), justify='center', anchor='center', bootstyle='dark.inverse')
    type_lbl.pack(fill='x', side='top')

    ###############################################################################
    input_frame = Frame(workspace_frame)
    input_frame.pack(fill='both', side='top', pady=5, expand=True)
    #------------------------------------------------------------------------------
    input_text_frame = Frame(input_frame)
    input_text_frame.pack(side='top', fill='both', expand=True)
    #------------------------------------------------------------------------------
    input_VScroll = Scrollbar(input_text_frame, orient="vertical", bootstyle="light-rounded")
    input_VScroll.pack(side='right', fill='y')
    #------------------------------------------------------------------------------
    input = Text(input_text_frame, takefocus=True, maxundo=-1, undo=True, wrap="char", yscrollcommand=input_VScroll.set)
    input.pack(fill='both', side='left', expand=True)
    input_VScroll.config(command=input.yview)
    #------------------------------------------------------------------------------
    input_details_frame = Frame(input_frame)
    input_details_frame.pack(fill='x', side='bottom')
    #------------------------------------------------------------------------------
    input_last_edit = Label(input_details_frame, text="****/**/** - **:**:** **")
    ToolTip(input_last_edit, "Last interaction with input", tooltip_style)
    input_last_edit.pack(side='left')
    #------------------------------------------------------------------------------
    input_cursor_position = Label(input_details_frame, text="1:0")
    input_cursor_position.pack(side='right')
    #------------------------------------------------------------------------------
    input_details = Label(input_details_frame, text="Characters: 0", justify='center', anchor='center')
    input_details.pack(fill='x', side='left', expand=True)
    def Input_Details_Update():
        input_cursor_position.config(text=input.index('insert').replace('.', ':'))
        details = "Characters: %s" % (len(input.get(1.0, 'end').strip('\n')))
        input_details.config(text=details)
        input_last_edit.config(text=datetime.datetime.now().strftime("%Y:%m:%d - %I:%M:%S %p"))
    input.bind('<ButtonPress-1>', lambda a:Input_Details_Update())
    input.bind('<ButtonRelease-1>', lambda a:Input_Details_Update())
    input.bind('<KeyPress>', lambda a:Input_Details_Update())
    input.bind('<KeyRelease>', lambda a:Input_Details_Update())
    #------------------------------------------------------------------------------
    input_actions_frame = Frame(input_frame)
    input_actions_frame.pack(side='bottom', fill='x')
    #------------------------------------------------------------------------------
    def RedoInput():
        try:
            input.edit_redo()
            Input_Details_Update()
        except _tkinter.TclError:
            pass
    redo_input = Button(input_actions_frame, text="redo", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :RedoInput())
    redo_input.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    def UndoInput():
        try:
            input.edit_undo()
            Input_Details_Update()
        except _tkinter.TclError:
            pass
    undo_input = Button(input_actions_frame, text="undo", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :UndoInput())
    undo_input.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    copy_input = Button(input_actions_frame, text="copy", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :pyperclip.copy(input.get(1.0, 'end').strip('\n')))
    copy_input.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    def ClearInput():
        input.delete(1.0, 'end')
        Input_Details_Update()
    clear_input = Button(input_actions_frame, text="clear", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :ClearInput())
    clear_input.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    def SaveInput2File():
        file = asksaveasfile(title="Save input to", defaultextension='txt', confirmoverwrite=True, mode='w', initialfile=str(random.randint(1000000000, 9999999999)))
        if file:
            open(file.name, 'w').write(input.get(1.0, 'end').strip("\n"))


    save2file_input = Button(input_actions_frame, text="save", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :SaveInput2File())
    save2file_input.pack(side='left',  fill='x', expand=True)
    ###############################################################################

    ###############################################################################
    output_frame = Frame(workspace_frame)
    output_frame.pack(fill='both', side='top', pady=5, expand=True)
    #------------------------------------------------------------------------------
    output_text_frame = Frame(output_frame)
    output_text_frame.pack(side='top', fill='both', expand=True)
    #------------------------------------------------------------------------------
    output_VScroll = Scrollbar(output_text_frame, orient="vertical", bootstyle="light-rounded")
    output_VScroll.pack(side='right', fill='y')
    #------------------------------------------------------------------------------
    output = Text(output_text_frame, takefocus=True, maxundo=-1, undo=True, wrap="char", yscrollcommand=output_VScroll.set)
    output.pack(fill='both', side='left', expand=True)
    output_VScroll.config(command=output.yview)
    #------------------------------------------------------------------------------
    output_details_frame = Frame(output_frame)
    output_details_frame.pack(fill='x', side='bottom')
    #------------------------------------------------------------------------------
    output_cursor_position = Label(output_details_frame, text="1:0")
    output_cursor_position.pack(side='right')
    #------------------------------------------------------------------------------
    output_last_edit = Label(output_details_frame, text="****/**/** - **:**:** **")
    ToolTip(output_last_edit, "Last interaction with output", tooltip_style)
    output_last_edit.pack(side='left')
    #------------------------------------------------------------------------------
    output_details = Label(output_details_frame, text="Characters: 0", justify='center', anchor='center')
    output_details.pack(fill='x', side='left', expand=True)
    def Output_Details_Update():
        output_cursor_position.config(text=output.index('insert').replace('.', ':'))
        details = "Characters: %s" % (len(output.get(1.0, 'end').strip('\n')))
        output_details.config(text=details)
        output_last_edit.config(text=datetime.datetime.now().strftime("%Y:%m:%d - %I:%M:%S %p"))
    output.bind('<ButtonPress-1>', lambda a:Output_Details_Update())
    output.bind('<ButtonRelease-1>', lambda a:Output_Details_Update())
    output.bind('<KeyPress>', lambda a:Output_Details_Update())
    output.bind('<KeyRelease>', lambda a:Output_Details_Update())
    #------------------------------------------------------------------------------
    output_actions_frame = Frame(output_frame)
    output_actions_frame.pack(side='bottom', fill='x')
    #------------------------------------------------------------------------------
    def RedoOutput():
        try:
            output.edit_redo()
            Output_Details_Update()
        except _tkinter.TclError:
            pass
    redo_output = Button(output_actions_frame, text="redo", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :RedoOutput())
    redo_output.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    def UndoOutput():
        try:
            output.edit_undo()
            Output_Details_Update()
        except _tkinter.TclError:
            pass
    undo_output = Button(output_actions_frame, text="undo", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :UndoOutput())
    undo_output.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    copy_output = Button(output_actions_frame, text="copy", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :pyperclip.copy(output.get(1.0, 'end').strip('\n')))
    copy_output.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    def ClearOutput():
        output.delete(1.0, 'end')
        Output_Details_Update()
    clear_output = Button(output_actions_frame, text="clear", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :ClearOutput())
    clear_output.pack(side='left', fill='x', expand=True)
    #------------------------------------------------------------------------------
    def SaveOutput2File():
        file = asksaveasfile(title="Save output to", defaultextension='txt', confirmoverwrite=True, mode='w', initialfile=str(random.randint(1000000000, 9999999999)))
        if file:
            open(file.name, 'w').write(output.get(1.0, 'end').strip("\n"))
    save2file_output = Button(output_actions_frame, text="save", bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :SaveOutput2File())
    save2file_output.pack(side='left', fill='x', expand=True)
    ###############################################################################
    execute = {
        'base16': {
            'safe': lambda :Encode_base16(string=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Decode_base16(string=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Encode_base16(string=data)
        },
        'base32': { # 'checksum': lambda data:
            'safe': lambda :Encode_base32(string=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Decode_base32(string=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Encode_base32(string=data)
        },
        'base58': {
            'safe': lambda :Encode_base58(string=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Decode_base58(string=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Encode_base58(string=data)
        },
        'base64': {
            'safe': lambda :Encode_base64(string=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Decode_base64(string=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Encode_base64(string=data)
        },
        'base85': {
            'safe': lambda :Encode_base85(string=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Decode_base85(string=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Encode_base85(string=data)
        },
        'base64.urlsafe': {
            'safe': lambda :Encode_base64_urlsafe(string=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Decode_base64_urlsafe(string=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Encode_base64_urlsafe(string=data)
        },
        'binary': {
            'safe': lambda :Binary_encrypt(text=input.get(1.0, 'end').strip('\n'), separator=binary_separatorVar.get()),
            'unsafe': lambda :Binary_decrypt(binary=input.get(1.0, 'end').strip('\n'), separator=binary_separatorVar.get()),
            # 'checksum': lambda data:Binary_encrypt(text=data, separator=binary_separatorVar.get())
        },
        'morse': {
            'safe': lambda :Morse_encrypt(text=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Morse_decrypt(morse=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Morse_encrypt(text=data)
        },
        'braille': {
            'safe': lambda :Braille.encode(text=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Braille.decode(braille=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Morse_encrypt(text=data)
        },
        'url': {
            'safe': lambda :Url.encode(url=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Url.decode(url=input.get(1.0, 'end').strip('\n')),
            # 'checksum': lambda data:Morse_encrypt(text=data)
        },
        'rot13': {
            'safe': lambda :Caesar_encode(string=input.get(1.0, 'end').strip('\n'), shift=13),
            'unsafe': lambda :Caesar_decode(string=input.get(1.0, 'end').strip('\n'), shift=13),
            # 'checksum': lambda data:Caesar_encode(string=data, shift=13)
        },
        'caesar': {
            'safe': lambda :Caesar_encode(string=input.get(1.0, 'end').strip('\n'), shift=caesar_shiftsVar.get()),
            'unsafe': lambda :Caesar_decode(string=input.get(1.0, 'end').strip('\n'), shift=caesar_shiftsVar.get()),
            # 'checksum': lambda data:Caesar_encode(string=data, shift=caesar_shiftsVar.get())
        },
        'hexdump': {
            'safe': lambda :HexDump(file=hexdump_file.get(), fence=hexdump_fenceVar.get(), type=hexdump_typeVar.get()),
            'unsafe': lambda :HexDump(file=hexdump_file.get(), fence=hexdump_fenceVar.get(), type=hexdump_typeVar.get())
        },
        'dummy': {
            'safe': lambda :Encode_dummy(string=input.get(1.0, 'end').strip('\n'), seperator=dummy_separatorVar.get()),
            'unsafe': lambda :Decode_dummy(string=input.get(1.0, 'end').strip('\n'), seperator=dummy_separatorVar.get()),
            # 'checksum': lambda data:Encode_dummy(string=data, seperator=dummy_separatorVar.get())
        },
        'md2': {
            'safe': lambda :_Md2_(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: _Md2_(string=data, type=hashing_typeVar.get())
        },
        'md4': {
            'safe': lambda :_Md4_(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: _Md4_(string=data, type=hashing_typeVar.get())
        },
        'md5': {
            'safe': lambda :Md5(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Md5(string=data, type=hashing_typeVar.get())
        },
        'sha1': {
            'safe': lambda :Sha1(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha1(string=data, type=hashing_typeVar.get())
        },
        'sha224': {
            'safe': lambda :Sha224(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha224(string=data, type=hashing_typeVar.get())
        },
        'sha256': {
            'safe': lambda :Sha256(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha256(string=data, type=hashing_typeVar.get())
        },
        'sha384': {
            'safe': lambda :Sha384(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha384(string=data, type=hashing_typeVar.get())
        },
        'sha512': {
            'safe': lambda :Sha512(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha512(string=data, type=hashing_typeVar.get())
        },
        'sha3.224': {
            'safe': lambda :Sha3_224(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha3_224(string=data, type=hashing_typeVar.get())
        },
        'sha3.256': {
            'safe': lambda :Sha3_256(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha3_256(string=data, type=hashing_typeVar.get())
        },
        'sha3.384': {
            'safe': lambda :Sha3_384(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha3_384(string=data, type=hashing_typeVar.get())
        },
        'sha3.512': {
            'safe': lambda :Sha3_512(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Sha3_512(string=data, type=hashing_typeVar.get())
        },
        'shake128': {
            'safe': lambda :Shake128(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get(), length=shake_lengthVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Shake128(string=data, type=hashing_typeVar.get(), length=shake_lengthVar.get())
        },
        'shake256': {
            'safe': lambda :Shake256(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get(), length=shake_lengthVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Shake256(string=data, type=hashing_typeVar.get(), length=shake_lengthVar.get())
        },
        'blake2s': {
            'safe': lambda :Black2s(string=input.get(1.0, 'end').strip('\n'), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Black2s(string=data, type=hashing_typeVar.get())
        },
        'blake2b': {
            'safe': lambda :Black2b(string=input.get(1.0, 'end').strip('\n'), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Black2b(string=data, type=hashing_typeVar.get())
        },
        'adler32': {
            'safe': lambda :Adler_32(string=input.get(1.0, 'end').strip('\n').encode()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Adler_32(string=data)
        },
        'ripemd160': {
            'safe': lambda :Ripemd_160(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Ripemd_160(string=data, type=hashing_typeVar.get())
        },
        'keccak224': {
            'safe': lambda :Keccak224(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Keccak224(string=data, type=hashing_typeVar.get())
        },
        'keccak256': {
            'safe': lambda :Keccak256(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Keccak256(string=data, type=hashing_typeVar.get())
        },
        'keccak384': {
            'safe': lambda :Keccak384(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Keccak384(string=data, type=hashing_typeVar.get())
        },
        'keccak512': {
            'safe': lambda :Keccak512(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Keccak512(string=data, type=hashing_typeVar.get())
        },
        'crc8': {
            'safe': lambda :_Crc8_(string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: _Crc8_(string=data, type=hashing_typeVar.get())
        },
        'crc16': {
            'safe': lambda :_Crc16_(string=input.get(1.0, 'end').strip('\n').encode()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: _Crc16_(string=data)
        },
        'crc32': {
            'safe': lambda :_Crc32_(string=input.get(1.0, 'end').strip('\n').encode()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: _Crc32_(string=data)
        },
        'ntlm': {
            'safe': lambda :Ntlm(string=input.get(1.0, 'end').strip('\n')),
            # 'unsafe': lambda :None,
            # 'checksum': lambda data: Ntlm(string=data)
        },
        'cmac': {
            'safe': lambda :Cmac(key=cmac_key.get().encode(), string=input.get(1.0, 'end').strip('\n').encode(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Cmac(string=data, key=cmac_key.get().encode(), type=hashing_typeVar.get())
        },
        'hmac': {
            'safe': lambda :Hmac(key=hmac_key.get(), msg=input.get(1.0, 'end').strip('\n'), digestmod=hmac_digestmodVar.get(), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Hmac(key=hmac_key.get(), msg=data, digestmod=hmac_digestmodVar.get(), type=hashing_typeVar.get())
        },
        'bcrypt': {
            'safe': lambda :Bcrypt_Encryption(string=input.get(1.0, 'end').strip('\n')),
            # 'unsafe': lambda :Bcrypt_Decryption(hashed_password=input.get(1.0, 'end').strip('\n'), password=bcrypt_salt.get()),
            # 'checksum': lambda data: Bcrypt_Encryption(string=data)
        },
        'poly1305': {
            'safe': lambda :_Poly1305_(key=poly1305_key.get(), string=input.get(1.0, 'end').strip('\n'), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data:_Poly1305_(key=poly1305_key.get(), string=data, type=hashing_typeVar.get())
        },
        'whirlpool': {
            'safe': lambda :Whirlpool(string=input.get(1.0, 'end').strip('\n'), type=hashing_typeVar.get()),
            # 'unsafe': lambda :None,
            'checksum': lambda data: Whirlpool(string=data, type=hashing_typeVar.get())
        },
        'aes128': {
            'safe': lambda :AES128_Encryption(data=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :AES128_Decryption(data=input.get(1.0, 'end').strip('\n'), key=aes128_key.get()),
            'checksum': lambda data:AES128_Encryption(data=data)
        },
        'punycode': {
            'safe': lambda :Punycode.encode(string=input.get(1.0, 'end').strip('\n')),
            'unsafe': lambda :Punycode.decode(string=input.get(1.0, 'end').strip('\n'))
        },
        # 'magic': {}, # detect hashing/encoding/encryption types.
    }

    selected_typeVar = StringVar()
    for i in sorted(list(execute.keys())):
        Radiobutton(types_frame, text=i.upper(), value=i, variable=selected_typeVar, bootstyle='toolbutton-dark', padding=15, takefocus=False, cursor='hand2', command=lambda :type_lbl.config(text='~ ' + selected_typeVar.get().upper() + ' ~')).pack(fill='x')

    def Run(method:str): # method= safe/unsafe [checksum]
        methods = ["safe", "unsafe"]# + ["checksum"]
        if selected_typeVar.get():
            type = selected_typeVar.get()
            if method in execute[type]:
                if method in methods:
                    try:
                        _out_ = execute[type][method]()
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
                            _out_ = execute[type][method](open(file=file, mode="rb").read())
                            input.delete(1.0, 'end')
                            input.insert(1.0, file)

                            output.delete(1.0, 'end')
                            output.insert(1.0, _out_)

                            Output_Details_Update()
                            Input_Details_Update()
                        except _tkinter.TclError:
                            pass

    ####################################################################
    WorkSpace_actions_Frame = Frame(workspace_frame) # SU=Safe/Unsafe
    WorkSpace_actions_Frame.pack(side='bottom', fill='x')
    Top_WorkSpace_actions_Frame = Frame(WorkSpace_actions_Frame) # SU=Safe/Unsafe
    Top_WorkSpace_actions_Frame.pack(side='top', fill='x')
    Bottom_WorkSpace_actions_Frame = Frame(WorkSpace_actions_Frame) # SU=Safe/Unsafe
    Bottom_WorkSpace_actions_Frame.pack(side='bottom', fill='x')
    #-------------------------------------------------------------------
    def Output2Input():
        if output.get(1.0, 'end').strip('\n'):
            input.delete(1.0, 'end')
            input.insert(1.0, output.get(1.0, 'end').strip('\n'))

            Output_Details_Update()
            Input_Details_Update()
    move_output2input = Button(Top_WorkSpace_actions_Frame, text="▲", padding=10, bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :Output2Input())
    move_output2input.pack(side='left')
    #-------------------------------------------------------------------
    Safe = Button(Top_WorkSpace_actions_Frame, text="Safe", bootstyle="success", padding=10, cursor='hand2', takefocus=False, command=lambda :Run(method="safe"))
    Safe.pack(side='left', fill='x', expand=True)
    #-------------------------------------------------------------------
    def FieldsSwap():
        inp = input.get(1.0, 'end').strip('\n')
        out = output.get(1.0, 'end').strip('\n')
        input.delete(1.0, 'end')
        output.delete(1.0, 'end')
        input.insert(1.0, out)
        output.insert(1.0, inp)

        Output_Details_Update()
        Input_Details_Update()
    output_switch = Button(Top_WorkSpace_actions_Frame, text="▲▼", padding=10, bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :FieldsSwap())
    output_switch.pack(side='left')
    #-------------------------------------------------------------------
    def Input2Output():
        if input.get(1.0, 'end').strip('\n'):
            output.delete(1.0, 'end')
            output.insert(1.0, input.get(1.0, 'end').strip('\n'))
            Output_Details_Update()
            Input_Details_Update()
    move_input2output = Button(Top_WorkSpace_actions_Frame, text="▼", padding=10, bootstyle='secondary', cursor='hand2', takefocus=False, command=lambda :Input2Output())
    move_input2output.pack(side='right')
    #-------------------------------------------------------------------
    UnSafe = Button(Top_WorkSpace_actions_Frame, text="Unsafe", bootstyle="danger", padding=10, cursor='hand2', takefocus=False, command=lambda :Run(method="unsafe"))
    UnSafe.pack(side='right', fill='x', expand=True)
    #-------------------------------------------------------------------
    Checksum = Button(Bottom_WorkSpace_actions_Frame, text="Checksum", bootstyle="primary", padding=10, cursor='hand2', takefocus=False, command=lambda :Run(method="checksum"))
    Checksum.pack(side='bottom', fill='x', expand=True)
    ####################################################################

    ################################################
    Action_menu.add_command(label="Safe", command=lambda :Run(method="safe"))
    Action_menu.add_command(label="Unsafe", command=lambda :Run(method="unsafe"))
    Action_menu.add_command(label="Checksum", command=lambda :Run(method="checksum"))
    ################################################
    Edit_Data_menu = Menu()
    Edit_menu.add_cascade(label="Data", menu=Edit_Data_menu)
    Edit_Data_menu.add_command(label="Swap input & output", command=lambda : FieldsSwap())
    # ----------------------------------------------
    Edit_Data_Input_menu = Menu()
    Edit_Data_menu.add_cascade(label="Input", menu=Edit_Data_Input_menu)
    Edit_Data_Input_menu.add_command(label="Redo", command=lambda :RedoInput())
    Edit_Data_Input_menu.add_command(label="Undo", command=lambda :UndoInput())
    Edit_Data_Input_menu.add_command(label="Copy", command=lambda :pyperclip.copy(input.get(1.0, 'end').strip('\n')))
    Edit_Data_Input_menu.add_command(label="Clear", command=lambda :ClearInput())
    Edit_Data_Input_menu.add_command(label="Save", command=lambda :SaveInput2File())
    Edit_Data_Input_menu.add_command(label="Move to output", command=lambda :Input2Output())
    # ----------------------------------------------
    Edit_Data_Output_menu = Menu()
    Edit_Data_menu.add_cascade(label="Output", menu=Edit_Data_Output_menu)
    Edit_Data_Output_menu.add_command(label="Redo", command=lambda: RedoOutput())
    Edit_Data_Output_menu.add_command(label="Undo", command=lambda: UndoOutput())
    Edit_Data_Output_menu.add_command(label="Copy", command=lambda: pyperclip.copy(output.get(1.0, 'end').strip('\n')))
    Edit_Data_Output_menu.add_command(label="Clear", command=lambda: ClearOutput())
    Edit_Data_Output_menu.add_command(label="Save", command=lambda: SaveOutput2File())
    Edit_Data_Output_menu.add_command(label="Move to Input", command=lambda :Input2Output())
    ################################################

    window.config(menu=menubar)
    window.mainloop()
Hexor()