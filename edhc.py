import _tkinter
import os
import re
import threading
import time
from tkinter import StringVar, BooleanVar, IntVar
from tkinter.ttk import *
from utils import monitor, edhc_util, _file_
from ttkbootstrap import Style, Window, Toplevel
from ttkbootstrap.tooltip import ToolTip
from ttkbootstrap.scrolled import ScrolledText, ScrolledFrame
from tkinter.filedialog import askopenfile, asksaveasfile
from ttkbootstrap.toast import ToastNotification
import pyperclip


def EDHC():  # EDHC=encode|encrypt,decode|decrypt,hash,crack
    window = Window(themename='darkly')  # yeti, darkly
    window.geometry(f"+{int(monitor(window)['width'] // 2.7)}+{monitor(window)['height'] // 4}")
    # window.resizable(False, False)
    # window.configure(background='darkred')
    window.iconbitmap("cracker.ico")
    window.title("EDHC")

    style = Style()

    # (('primary', '#375a7f'), ('secondary', '#444444'), ('success', '#00bc8c'), ('info', '#3498db'), ('warning', '#f39c12'), ('danger', '#e74c3c'), ('light', '#ADB5BD'), ('dark', '#303030'), ('bg', '#222222'), ('fg', '#ffffff'), ('selectbg', '#555555'), ('selectfg', '#ffffff'), ('border', '#222222'), ('inputfg', '#ffffff'), ('inputbg', '#2f2f2f'), ('active', '#1F1F1F'))

    upper_frame = Frame(window)
    upper_frame.pack(side='top', fill='both', expand=True)
    ##
    input_frame = Frame(upper_frame)
    input_frame.pack(expand=True, fill='both', side='right')
    ##
    input_settings_frame = Frame(input_frame)
    input_settings_frame.pack(side='left', fill='y')
    ##
    MoveDownBtn = Button(input_settings_frame, text='▼', width=2, bootstyle='link', cursor='hand2', takefocus=False, command=lambda: MoveDown())
    MoveDownBtn.pack(side='bottom')
    ToolTip(MoveDownBtn, "Move input content to output.", bootstyle='secondary.INVERSE')
    ##
    input_font_size_inc = Button(input_settings_frame, text='+', width=1, bootstyle='link.success', takefocus=False, cursor='hand2', command=lambda: edhc_util.increase_font(input._text))  # increase
    input_font_size_inc.pack(side='top', pady=2)
    ToolTip(input_font_size_inc, "Increase input font size", bootstyle='secondary.INVERSE')
    ##
    input_font_size_dec = Button(input_settings_frame, text='-', width=1, bootstyle='link.danger', takefocus=False, cursor='hand2', command=lambda: edhc_util.decrease_font(input._text))  # decrease
    input_font_size_dec.pack(side='top')
    ToolTip(input_font_size_dec, "Decrease input font size", bootstyle='secondary.INVERSE')
    ##
    clear_input_field = Button(input_settings_frame, text='x', width=1, bootstyle='link.secondary', takefocus=False, cursor='hand2', command=lambda: input._text.delete(1.0, 'end'))  # decrease
    clear_input_field.pack(side='top')
    ToolTip(clear_input_field, "Clear input field", bootstyle='secondary.INVERSE')
    ##
    Copy_inputContent = Button(input_settings_frame, text='📝', width=2, bootstyle='link.primary', takefocus=False, cursor='hand2', command=lambda: pyperclip.copy(input._text.get(1.0, 'end')))  # decrease
    Copy_inputContent.pack(side='top')
    ToolTip(Copy_inputContent, "Copy input field content", bootstyle='secondary.INVERSE')
    ##
    options_frame = Frame(input_frame)
    options_frame.pack(pady=5, fill='x')
    ##
    input_information_frame = Frame(input_frame)
    input_information_frame.pack(side='top', fill='x')
    ##
    input_information_lbl = Label(input_information_frame)
    input_information_lbl.pack()
    ##
    lower_frame = Frame(window)
    lower_frame.pack(side='bottom', fill='both', expand=True)
    output_frame = Frame(lower_frame)
    output_frame.pack(expand=True, fill='both', side='right')
    ##
    output_settings_frame = Frame(output_frame)
    output_settings_frame.pack(side='left', fill='y')

    ##
    def Update_output_information():
        input_data = input._text.get(1.0, 'end')
        output_data = output._text.get(1.0, 'end')
        input_information_lbl.config(text="%s character, %s line, type: %s" % (
            len(str(input_data)) - 1, len(str(input_data).splitlines()), typeVar.get()))
        output_information_lbl.config(text="%s character, %s line, type: %s" % (
            len(str(output_data)) - 1, len(str(output_data).splitlines()), typeVar.get()))
    ##
    def MoveUp():
        data = output._text.get(1.0, 'end').strip()
        if len(str(data).strip()) > 0:
            input._text.delete(1.0, 'end')
            input._text.insert(1.0, data)

    MoveUpBtn = Button(output_settings_frame, text='▲', width=2, bootstyle='link', cursor='hand2', takefocus=False,
                       command=lambda: MoveUp())
    MoveUpBtn.pack(side='top')
    ToolTip(MoveUpBtn, "Move output content to input.", bootstyle='secondary.INVERSE')

    def SaveOutput():
        file = asksaveasfile(defaultextension=typeVar.get(), title='Save as')
        if file:
            if file.name:
                open(file.name, 'w').write(output._text.get(1.0, 'end'))
                ToastNotification(title='Saved successfully',
                                  message='Output successfully saved to %s (%s)' % (file.name, _file_.size(file.name)),
                                  bootstyle='success', icon='\u2713', alert=False, duration=3500).show_toast()
                Update_output_information()

    SaveOutputBtn = Button(output_settings_frame, text='\U0001f4be', width=2, bootstyle='link', cursor='hand2',
                       takefocus=False, command=lambda: SaveOutput())
    SaveOutputBtn.pack(side='top')
    ToolTip(MoveUpBtn, "Save output content to a file", bootstyle='secondary.INVERSE')
    ##
    output_font_size_inc = Button(output_settings_frame, text='+', width=1, bootstyle='link.success', takefocus=False,
                                  cursor='hand2', command=lambda: edhc_util.increase_font(output._text))  # increase
    output_font_size_inc.pack(side='bottom', pady=2)
    ToolTip(output_font_size_inc, "Increase output font size", bootstyle='secondary.INVERSE')
    ##
    output_font_size_dec = Button(output_settings_frame, text='-', width=1, bootstyle='link.danger', takefocus=False,
                                  cursor='hand2', command=lambda: edhc_util.decrease_font(output._text))  # decrease
    output_font_size_dec.pack(side='bottom')
    ToolTip(output_font_size_dec, "Decrease output font size", bootstyle='secondary.INVERSE')
    ##
    def Clear_output():
        output._text.config(state='normal')
        output._text.delete(1.0, 'end')
        output._text.config(state='disabled')
        Update_output_information()

    output_font_size_dec = Button(output_settings_frame, text='x', width=1, bootstyle='link.secondary', takefocus=False,
                                  cursor='hand2', command=lambda: Clear_output())  # decrease
    output_font_size_dec.pack(side='bottom')
    ToolTip(output_font_size_dec, "Clear output field", bootstyle='secondary.INVERSE')
    ##
    output_content_copy = Button(output_settings_frame, text='📝', width=2, bootstyle='link.primary', takefocus=False,
                                 cursor='hand2',
                                 command=lambda: pyperclip.copy(output._text.get(1.0, 'end')))  # decrease
    output_content_copy.pack(side='bottom')
    ToolTip(output_content_copy, "Copy output field content", bootstyle='secondary.INVERSE')

    def MoveDown():
        data = input._text.get(1.0, 'end').strip()
        if len(str(data).strip()) > 0:
            output._text.config(state='normal')
            output._text.delete(1.0, 'end')
            output._text.insert(1.0, data)
            output._text.config(state='disabled')
            Update_output_information()

    getFromFile = Button(options_frame, text='open file', bootstyle='primary,outline', cursor='hand2', takefocus=False)
    ToolTip(getFromFile, "Insert input from a file", bootstyle='secondary.INVERSE')
    getFromFile.pack(side='right', padx=7, ipadx=5)

    def Run():
        if len(str(input._text.get(1.0, 'end'))) > 0:
            data = input._text.get(1.0, 'end').strip('\n')
            Type = typeVar.get()
            do = EncOrDecVar.get()

            def Enable_it():
                output._text.config(state='normal')
                output._text.delete(1.0, 'end')

            if Type == 'base16':
                Enable_it();
                output._text.insert(1.0,
                                    edhc_util.Encode_base16(data) if do == 'Encode' else edhc_util.Decode_base16(data))
            elif Type == 'base32':
                Enable_it();
                output._text.insert(1.0,
                                    edhc_util.Encode_base32(data) if do == 'Encode' else edhc_util.Decode_base32(data))
            elif Type == 'base58':
                Enable_it();
                output._text.insert(1.0,
                                    edhc_util.Encode_base58(data) if do == 'Encode' else edhc_util.Decode_base58(data))
            elif Type == 'base64':
                Enable_it();
                output._text.insert(1.0,
                                    edhc_util.Encode_base64(data) if do == 'Encode' else edhc_util.Decode_base64(data))
            elif Type == 'base85':
                Enable_it();
                output._text.insert(1.0,
                                    edhc_util.Encode_base85(data) if do == 'Encode' else edhc_util.Decode_base85(data))
            elif Type == 'base64.urlsafe':
                Enable_it();
                output._text.insert(1.0, edhc_util.Encode_base64_urlsafe(
                    data) if do == 'Encode' else edhc_util.Decode_base64_urlsafe(data))
            elif Type == 'binary':
                print("Still working on it")
                # Enable_it();output._text.insert(1.0, edhc_util.Encode_base64_urlsafe(data) if do == 'Encode' else edhc_util.Decode_base64_urlsafe(data))
            elif Type == 'morse':
                Enable_it();
                output._text.insert(1.0,
                                    edhc_util.Morse_encrypt(data) if do == 'Encode' else edhc_util.Morse_decrypt(data))
            elif Type == 'rot13':
                Enable_it();
                output._text.insert(1.0, edhc_util.Caesar_encode(string=data,
                                                                 shift=13) if do == 'Encode' else edhc_util.Caesar_encode(
                    string=data, shift=-13))
            elif Type == 'caesar':
                Enable_it();
                output._text.insert(1.0, edhc_util.Caesar_encode(string=data,
                                                                 shift=ShiftsVar.get()) if do == 'Encode' else edhc_util.Caesar_encode(
                    string=data, shift=-ShiftsVar.get()))
            elif Type == 'hexdump':
                file = askopenfile(title='Pick a file for hexdump')
                if file:
                    saveAs = asksaveasfile(confirmoverwrite=True, title='Save hexdumpe output to',
                                           defaultextension='hexdump')
                    if saveAs:
                        open(saveAs.name, 'w').write(edhc_util.HexDump(file=file.name, type=HexDump_formatVar.get(),
                                                                       fence=HexDump_fenceVar.get()))
            elif Type == 'magic':
                print("Still working on it")
                # Enable_it();output._text.insert(1.0, edhc_util.Encode_base64_urlsafe(data) if do == 'Encode' else edhc_util.Decode_base64_urlsafe(data))
            elif Type == 'dummy':
                Enable_it();
                output._text.insert(1.0,
                                    edhc_util.Encode_dummy(string=data) if do == 'Encode' else edhc_util.Decode_dummy(
                                        string=data))


            elif Type == 'md5':
                Enable_it();
                output._text.insert(1.0, edhc_util.Md5(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha1':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha1(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha224':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha224(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha256':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha256(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha384':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha384(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha512':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha512(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha3.224':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha3_224(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha3.256':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha3_256(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha3.384':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha3_384(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'sha3.512':
                Enable_it();
                output._text.insert(1.0, edhc_util.Sha3_512(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'shake.128':
                Enable_it();
                output._text.insert(1.0, edhc_util.Shake128(string=data, type=HashTypeVar.get()[0:3],
                                                            length=HashLengthVar.get()))
            elif Type == 'shake.256':
                Enable_it();
                output._text.insert(1.0, edhc_util.Shake256(string=data, type=HashTypeVar.get()[0:3],
                                                            length=HashLengthVar.get()))
            elif Type == 'black2s':
                Enable_it();
                output._text.insert(1.0, edhc_util.Black2s(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'blake2b':
                Enable_it();
                output._text.insert(1.0, edhc_util.Black2b(string=data, type=HashTypeVar.get()[0:3]))
            elif Type == 'hmac':
                Enable_it();
                output._text.insert(1.0, edhc_util.Hmac(key=HmacKey.get(), msg=data,
                                                        digestmod=DigestModVar.get().replace('.', '_'),
                                                        type=HashTypeVar.get()[0:3]))

            output._text.config(state='disabled')
            Update_output_information()

    def InsertFromFile():
        file = askopenfile(title='Pick a file')
        if file:
            if os.path.exists(file.name) and os.path.isfile(file.name):
                try:
                    # print(os.path.getsize(file.name) / 1024)
                    input._text.delete(1.0, 'end')
                    input._text.insert(1.0, open(file.name, 'r').read())
                    if autoRunVar.get():
                        Run()
                except UnicodeDecodeError:
                    print(os.path.getsize(file.name))
                    input._text.delete(1.0, 'end')
                    input._text.insert(1.0, open(file.name, 'rb').read())
                    if autoRunVar.get():
                        Run()
                Update_output_information()

    getFromFile['command'] = lambda: InsertFromFile()
    ##
    input = ScrolledText(input_frame, background='darkred', height=15, font=("' 10"), autohide=True)
    input.pack(expand=True, fill='both', side='top')
    input._text.bind('<KeyPress>', lambda a: Update_output_information())
    input._text.bind('<KeyRelease>', lambda a: Update_output_information())
    ##
    output = ScrolledText(output_frame, background='darkred', height=15, font=("' 10"), state='disabled', autohide=True)
    output.pack(expand=True, fill='both', side='top')
    ##
    RunFrame = Frame(output_frame)
    RunFrame.pack(side='bottom', fill='x')
    RunBtn = Button(RunFrame, text="Run", cursor='hand2', takefocus=False, command=lambda: Run(), bootstyle='success')
    # ToolTip(RunBtn, "Execute the prepared process", bootstyle='secondary.INVERSE')
    RunBtn.pack(expand=True, padx=2, fill='x', side='right')
    ##
    output_information_frame = Frame(output_frame)
    output_information_frame.pack( side='bottom', fill='x')
    ##
    output_information_lbl = Label(output_information_frame)
    output_information_lbl.pack()

    typeVar = StringVar(value=edhc_util.All_types()[0])
    input_information_lbl.config(text="0 character, 1 line, type: %s" % typeVar.get())
    output_information_lbl.config(text="0 character, 1 line, type: %s" % typeVar.get())
    type = Combobox(options_frame, justify='left', textvariable=typeVar, width=len(str(max(edhc_util.All_types()))) + 4,
                    values=edhc_util.All_types(), bootstyle='primary', state='readonly')
    ToolTip(type, "Type of encoding/hashing,encrypting you want to use there is %s type." % len(edhc_util.All_types()),
            bootstyle='secondary.INVERSE')

    def TypeChanged():
        value = typeVar.get()
        if value in edhc_util.all['encode']:
            EncOrDec['text'] = 'Encode'
            EncOrDecVar.set('Encode')
        elif value in edhc_util.all['hash']:
            EncOrDec['text'] = 'Hash'
            EncOrDecVar.set('Hash')
        Update_output_information()
        if value in ['caesar']:
            Shifts.pack(side='left')
        elif value in ['hexdump']:
            EncOrDec.pack_forget()
            Shifts.pack_forget()
            HashType.pack_forget()
            HashLength.pack_forget()
            DigestMod.pack_forget()
            HmacKey.pack_forget()
            HexDump_format.pack(side='left', padx=3)
            HexDump_fence.pack(side='left')
        elif value in edhc_util.all['hash']:
            HashType.pack(side='left')
            if value == 'hmac':
                DigestMod.pack(side='left', padx=3)
                HmacKey.pack(side='left')
                Shifts.pack_forget()
                HexDump_format.pack_forget()
                HexDump_fence.pack_forget()
            elif value in ['shake.128', 'shake.256']:
                HashLength.pack(side='left', padx=3)
                Shifts.pack_forget()
            else:
                HashLength.pack_forget()
                DigestMod.pack_forget()
                HmacKey.pack_forget()
                HexDump_fence.pack_forget()
                HexDump_format.pack_forget()
        else:
            Shifts.pack_forget()
            HexDump_fence.pack_forget()
            HexDump_format.pack_forget()
            ##
            HashType.pack_forget()
            HashLength.pack_forget()
            ##
            HmacKey.pack_forget()
            DigestMod.pack_forget()
            ##
            EncOrDec.pack(side='left')
        if autoRunVar.get():
            Run()

    type.bind('<<ComboboxSelected>>', lambda a: TypeChanged())
    type.pack(padx=5, side='left')

    EncOrDecVar = StringVar(value='Encode')
    EncOrDec = Button(options_frame, text='Encode', bootstyle='link.success', takefocus=False)
    ToolTip(EncOrDec, "Encode/Encrypt/Hash - Decode/Decrypt/Crack", bootstyle='secondary.INVERSE')
    ##
    ShiftsVar = IntVar(value=3)
    ShiftsVar.set(3)
    Shifts = Spinbox(options_frame, width=5, justify='center', takefocus=False, from_=1, to=100, textvariable=ShiftsVar,
                     state='readonly', command=lambda: Run())
    ToolTip(Shifts, "Shift times (only int)", bootstyle='secondary.INVERSE')
    Shifts.bind('<Button-1>', lambda a: Run() if autoRunVar.get() else None)
    ##
    HexDump_fenceVar = StringVar(value='|')
    HexDump_fence = Combobox(options_frame, justify='left', textvariable=HexDump_fenceVar, width=1,
                             values=['|', '-', '~'], bootstyle='primary', state='readonly')
    ToolTip(HexDump_fence, "Fence for the plaintext table", bootstyle='secondary.INVERSE')
    HexDump_fence.bind('<<ComboboxSelected>>', lambda a: Run() if autoRunVar.get() else None)
    ##
    HexDump_formatVar = StringVar(value='hex')
    HexDump_format = Combobox(options_frame, justify='left', textvariable=HexDump_formatVar, width=3,
                              values=['hex', 'bin'], bootstyle='primary', state='readonly')
    ToolTip(HexDump_format, "Display data lines as hexadecimal OR binary format", bootstyle='secondary.INVERSE')
    HexDump_format.bind('<<ComboboxSelected>>', lambda a: Run() if autoRunVar.get() else None)
    ##
    HashTypeVar = StringVar(value='hexdigest')
    HashType = Combobox(options_frame, justify='left', textvariable=HashTypeVar, width=10,
                        values=['hexdigest', 'digest'], bootstyle='primary', state='readonly')
    ToolTip(HashType, "Type of hashing output hexadecimal OR digest", bootstyle='secondary.INVERSE')
    HashType.bind('<<ComboboxSelected>>', lambda a: Run() if autoRunVar.get() else None)
    ##
    DigestModVar = StringVar(value='md5')
    DigestMod = Combobox(options_frame, justify='left', textvariable=DigestModVar, width=8,
                         values=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512', 'sha3.224', 'sha3.256',
                                 'sha3.384', 'sha3.512', 'black2s', 'blake2b'], bootstyle='primary', state='readonly')
    DigestMod.bind('<<ComboboxSelected>>', lambda a: Run() if autoRunVar.get() else None)
    ToolTip(DigestMod, "Type of hmac hashing", bootstyle='secondary.INVERSE')
    ##
    HashLengthVar = IntVar(value=3)
    HashLengthVar.set(3)
    HashLength = Spinbox(options_frame, width=5, justify='center', takefocus=False, from_=1, to=9999, textvariable=HashLengthVar, state='readonly', command=lambda: Run())
    HashLength.bind('<Button-1>', lambda a: Run() if autoRunVar.get() else None)
    ToolTip(HashLength, "Length of the hash", bootstyle='secondary.INVERSE')
    ##
    HmacKey = Entry(options_frame)
    HmacKey.bind('<KeyPress>', lambda a: Run() if autoRunVar.get() else None)
    HmacKey.bind('<KeyRelease>', lambda a: Run() if autoRunVar.get() else None)
    ToolTip(HmacKey, "The key of the hashed string", bootstyle='secondary.INVERSE')

    def EncOrDecFunc():
        value = EncOrDec['text']
        if value == 'Encode' or value == 'Hash':
            if typeVar.get() in edhc_util.all['encode']:
                EncOrDec['text'] = 'Decode'
                EncOrDec['bootstyle'] = 'link.danger'
                EncOrDecVar.set('Decode')
            elif typeVar.get() in edhc_util.all['hash']:
                EncOrDec['text'] = 'Crack'
                EncOrDec['bootstyle'] = 'link.danger'
                EncOrDecVar.set('Crack')
        else:
            if typeVar.get() in edhc_util.all['encode']:
                EncOrDec['text'] = 'Encode'
                EncOrDec['bootstyle'] = 'link.success'
                EncOrDecVar.set('Encode')
            elif typeVar.get() in edhc_util.all['hash']:
                EncOrDec['text'] = 'Hash'
                EncOrDec['bootstyle'] = 'link.success'
                EncOrDecVar.set('Hash')
        if autoRunVar.get():
            Run()
        Update_output_information()

    EncOrDec.bind('<Button-1>', lambda a: EncOrDecFunc())
    EncOrDec.pack(side='left')

    autoRunVar = BooleanVar()
    autoRun = Checkbutton(options_frame, text='auto run', variable=autoRunVar, cursor='hand2',
                          bootstyle='primary-round-toggle', command=lambda: Run() if autoRunVar.get() else None)

    def IsAutoRun():
        value = autoRunVar.get()
        if value:
            # I get the true value of the checkbutton after i release the button
            # then True == False and False == True.
            input._text.unbind('<KeyPress>')
            input._text.unbind('<KeyRelease>')
        else:
            input._text.bind('<KeyPress>', lambda a: Run())
            input._text.bind('<KeyRelease>', lambda a: Run())

    autoRun.bind('<Button-1>', lambda a: IsAutoRun())
    ToolTip(autoRun, "Auto run on key press", bootstyle='secondary.INVERSE')
    autoRun.pack(side='right', padx=7)

    window.mainloop()


EDHC()
