def HexDump(file, type: str = 'hex', fence: str = '|'):
    try:
        table = ""
        with open(file, "rb") as f:
            n = 0
            b = f.read(16)

            while b:
                if type == 'hex':
                    s1 = " ".join([f"{i:02x}" for i in b])  # hex string
                    s1 = s1[0:23] + " " + s1[23:]  # insert extra space between groups of 8 hex values
                    width = 48
                else:
                    s1 = " ".join([f"{i:08b}" for i in b])  # binary string
                    s1 = s1[0:71] + " " + s1[71:]  # insert extra space between groups of 8 binary values
                    width = 144
                # as> 72<here>20<here>61
                # 72 74 20 61 72 67 70 61

                s2 = "".join([chr(i) if 32 <= i <= 127 else "." for i in b])  # ascii string; chained comparison
                # 32 -> 127 (this is every single possible character other than spaces and else)
                table += f"{n * 16:08x}  {s1:<{width}}  {fence}{s2}{fence}\n"  # make (this.line) of table
                # {s1:<48} is the below between brackets (spaces also counted):
                # (72 74 20 61 72 67 70 61  72 73 65 0d 0a 0d 0a 70)
                n += 1
                b = f.read(16)
            f.close()
        return table.strip()
    except Exception as e:
        return str(e)
