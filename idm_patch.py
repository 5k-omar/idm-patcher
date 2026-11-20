import ctypes
import os
import struct
import subprocess
import sys
import time
import webbrowser
import winreg

DISCORD     = "https://discord.gg/cW9DdBC5NY"
DEFAULT_EXE = os.path.join(
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
    "Internet Download Manager", "IDMan.exe")

REG_PATH   = r"Software\DownloadManager"
REG_VALUES = (("FName", "Catrine"), ("LName", "(omar)"), ("LstCheck", "12/06/6767"))


def console():
    if sys.stdout is not None:
        return
    try:
        ctypes.windll.kernel32.AttachConsole(-1)
        sys.stdout = open("CONOUT$", "w", encoding="utf-8", errors="replace")
        sys.stderr = sys.stdout
    except Exception:
        pass


def pe_info(data):
    if data[:2] != b"MZ":
        raise ValueError("not an exe")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe+4] != b"PE\0\0":
        raise ValueError("no PE header")
    if struct.unpack_from("<H", data, pe+4)[0] != 0x14C:
        raise ValueError("not 32-bit x86")
    nsec = struct.unpack_from("<H", data, pe+6)[0]
    opt  = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x10B:
        raise ValueError("not PE32")
    base    = struct.unpack_from("<I", data, opt+28)[0]
    imp_rva = struct.unpack_from("<I", data, opt+104)[0]   # DataDirectory[1] (import)
    soff    = opt + struct.unpack_from("<H", data, pe+20)[0]
    sects   = []
    for i in range(nsec):
        s = soff + i*40
        vsize, va, rawsize, raw = struct.unpack_from("<IIII", data, s+8)
        chars = struct.unpack_from("<I", data, s+36)[0]
        sects.append((va, vsize, raw, rawsize, chars))
    return {"base": base, "imp": imp_rva, "sect": sects}


def rva_to_off(info, rva):
    for va, vsize, raw, rawsize, _ in info["sect"]:
        if va <= rva < va + max(vsize, rawsize):
            return raw + (rva - va)
    raise ValueError(f"rva {rva:#x} not mapped")


def code_span(info):
    for va, vsize, raw, rawsize, chars in info["sect"]:
        if chars & 0x20000000:
            return raw, raw + rawsize
    raise ValueError("no executable section")


def iat_map(data, info):
    table = {}
    off   = rva_to_off(info, info["imp"])
    while True:
        desc = data[off:off+20]
        if len(desc) < 20 or desc == b"\0"*20:
            break
        oft, _, _, _, first = struct.unpack("<IIIII", desc)
        i = 0
        while True:
            t     = rva_to_off(info, (oft or first) + i*4)
            thunk = struct.unpack_from("<I", data, t)[0]
            if thunk == 0:
                break
            if not thunk & 0x80000000:
                n    = rva_to_off(info, thunk + 2)
                name = data[n:data.index(b"\0", n)].decode("ascii", "replace")
                table.setdefault(name, info["base"] + first + i*4)
            i += 1
        off += 20
    return table


def status_branch(data, call_off):
    # mov r,eax ; cmp|test r,? ; jcc  →  (offset, length) or None
    p = call_off + 5
    if p + 2 >= len(data) or data[p] != 0x8B:
        return None
    modrm = data[p+1]
    if (modrm & 0xC0) != 0xC0 or (modrm & 7) != 0:    # mod=11, rm=eax
        return None
    reg = (modrm >> 3) & 7
    q   = p + 2
    if data[q] == 0x83:                                 # cmp r, imm8
        if (data[q+1] & 0xC0) != 0xC0 or ((data[q+1] >> 3) & 7) != reg:
            return None
        q += 3
    elif data[q] in (0x3B, 0x85):                      # cmp r,r/m  |  test r,r/m
        if ((data[q+1] >> 3) & 7) != reg:
            return None
        q += 2
    else:
        return None
    if data[q] in (0x74, 0x75, 0xEB):
        return q, 2
    if data[q] == 0x0F and data[q+1] in (0x84, 0x85, 0xE9):
        return q, 6
    return None


def find_status_sites(data, info, imap):
    exit_va = imap.get("ExitProcess")
    if not exit_va:
        raise ValueError("ExitProcess not imported")
    pat   = b"\xff\x15" + struct.pack("<I", exit_va)
    cs, ce = code_span(info)
    sites  = []
    pos    = cs
    while True:
        i = data.find(pat, pos)
        if i < 0 or i >= ce:
            break
        pos = i + 6
        for back in range(i-1, max(cs, i-0x220), -1):
            if data[back] != 0xE8:
                continue
            rel = struct.unpack_from("<i", data, back+1)[0]
            tgt = back + 5 + rel
            if not (cs <= tgt < ce):
                continue
            found = status_branch(data, back)
            if not found:
                continue
            j, size = found
            if j >= i or b"\xe8" not in data[j:i]:
                continue
            dest = j + size + (struct.unpack_from("<b", data, j+1)[0] if size == 2
                               else struct.unpack_from("<i", data, j+2)[0])
            if not (i < dest <= i + 0x40):
                continue
            sites.append({"off": j, "size": size, "kind": "status branch"})

            for k in range(j + size, i):
                if data[k] == 0xE8:
                    box = k + 5 + struct.unpack_from("<i", data, k+1)[0]
                    if cs <= box < ce:
                        sites.append({"off": box, "size": 3, "kind": "message box"})
                    break
            break
    return sites



def find_dialog_sites(data, info, imap):
    dlg_va = imap.get("DialogBoxIndirectParamW")
    if not dlg_va:
        return []
    dlg_pat = b"\xff\x15" + struct.pack("<I", dlg_va)
    cs, ce  = code_span(info)
    sites   = []
    pos     = cs
    while True:
        t = data.find(b"\x85\xc0\x0f\x84", pos)
        if t < 0 or t >= ce:
            break
        pos = t + 4
        if t - 7 < cs:
            continue
        j = t - 7
        if data[j] not in (0x74, 0x75, 0xEB):
            continue
        if data[t-5] != 0xE8:
            continue
        rel     = struct.unpack_from("<i", data, t-4)[0]
        builder = t - 5 + 5 + rel
        if not (cs <= builder < ce):
            continue
        if dlg_pat not in data[builder:builder+0x800]:
            continue
        sites.append({"off": j, "size": 2, "kind": "dialog skip"})
    return sites


def locate(data, info):
    imap  = iat_map(data, info)
    sites = find_status_sites(data, info, imap) + find_dialog_sites(data, info, imap)
    uniq  = {}
    for s in sites:
        uniq[s["off"]] = s
    return sorted(uniq.values(), key=lambda s: s["off"])



def scan(exe):
    with open(exe, "rb") as f:
        data = bytearray(f.read())
    return data, locate(data, pe_info(data))


def site_bytes(data, s):
    off = s["off"]
    if s["kind"] == "message box":
        p = b"\x31\xC0\xC3"
        return p, data[off:off+3] == p
    if s.get("size") == 6:
        dest = off + 6 + struct.unpack_from("<i", data, off+2)[0]
        return b"\xE9" + struct.pack("<i", dest - (off+5)) + b"\x90", data[off] == 0xE9
    return b"\xEB", data[off] == 0xEB


def byte_rows(data, sites, span=8):
    rows = []
    for s in sites:
        off    = s["off"]
        patch, done = site_bytes(data, s)
        chunk  = bytes(data[off:off+span])
        after  = bytearray(chunk)
        after[:len(patch)] = patch
        rows.append((off, chunk, bytes(after), not done, s["kind"]))
    return rows


def print_preview(data, sites, log, span=8):
    for off, before, after, changed, kind in byte_rows(data, sites, span):
        done = "" if changed else "   (done)"
        log(f"  {off:#06x}  {kind:<15}before  " + " ".join(f"{x:02X}" for x in before))
        log(f"  {' '*6}  {' '*15}after   " + " ".join(f"{x:02X}" for x in after) + done)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate():
    args = " ".join(f'"{a}"' for a in sys.argv[1:])
    rc   = ctypes.windll.shell32.ShellExecuteW(
               None, "runas", sys.executable,
               f'"{sys.executable}" {args}', None, 1)
    if rc <= 32:
        sys.exit("UAC refused")
    sys.exit(0)


def close_idm():
    subprocess.run(["taskkill", "/IM", "IDMan.exe"],       capture_output=True)
    time.sleep(1)
    subprocess.run(["taskkill", "/IM", "IDMan.exe", "/F"], capture_output=True)
    time.sleep(0.5)


def write_registry(log):
    try:
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, REG_PATH, 0, winreg.KEY_SET_VALUE)
    except OSError as e:
        log(f"registry: {e}")
        return
    for name, val in REG_VALUES:
        try:
            cur, _ = winreg.QueryValueEx(k, name)
        except OSError:
            cur = None
        if cur != val:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, val)
            log(f"registry {name} = {val}")
    k.Close()


def apply_patch(exe, log=print):
    exe    = os.path.abspath(exe)
    backup = exe + ".orig"
    if not os.path.isfile(exe):
        log(f"missing {exe}")
        return False

    try:
        data, sites = scan(exe)
    except ValueError as e:
        log(f"unsupported file: {e}")
        return False

    log(f"{os.path.basename(exe)}  {len(data)} bytes")
    log("sites: " + (", ".join(f"{s['kind']} @ {s['off']:#06x}" for s in sites) or "none"))
    if not sites:
        log("no match for this build, file left alone")
        return False

    print_preview(data, sites, log)
    todo = [s for s in sites if not site_bytes(data, s)[1]]
    if not todo:
        log("already patched")
        write_registry(log)
        return True

    close_idm()
    if not os.path.isfile(backup):
        with open(backup, "wb") as f:
            f.write(bytes(data))
        log(f"backup {backup}")

    for s in todo:
        off = s["off"]
        patch, _ = site_bytes(data, s)
        data[off:off+len(patch)] = patch

    with open(exe, "r+b") as f:
        f.seek(0)
        f.write(data)
        f.truncate()
        f.flush()
        os.fsync(f.fileno())

    with open(exe, "rb") as f:
        check = f.read()
    if any(not site_bytes(check, s)[1] for s in sites):
        log("write check failed")
        return False

    write_registry(log)
    log(f"patched {len(todo)} site(s). start IDM")
    return True


def restore(exe, log=print):
    exe    = os.path.abspath(exe)
    backup = exe + ".orig"
    if not os.path.isfile(backup):
        log("no .orig backup beside the exe")
        return False
    close_idm()
    with open(backup, "rb") as src, open(exe, "r+b") as dst:
        dst.write(src.read())
        dst.truncate()
    log("original restored")
    return True


def launch_gui(exe):
    import tkinter as tk
    from tkinter import filedialog

    win = tk.Tk()
    win.title("IDM Patcher")
    win.geometry("620x520")
    win.configure(bg="#15171c")
    win.resizable(False, False)

    tk.Label(win, text="IDM Patcher", bg="#15171c", fg="#ededed",
             font=("Segoe UI", 13, "bold")).pack(pady=(16, 2))
    tk.Label(win, text="status branch + message box + dialog skip, name and date written",
             bg="#15171c", fg="#8b9098", font=("Segoe UI", 9)).pack()

    path = tk.StringVar(value=exe)
    row  = tk.Frame(win, bg="#15171c")
    row.pack(fill="x", padx=16, pady=12)
    tk.Entry(row, textvariable=path, bg="#0e1014", fg="#dcdcdc", relief="flat",
             insertbackground="#dcdcdc").pack(side="left", fill="x", expand=True, ipady=5)
    tk.Button(row, text="...", relief="flat", bg="#232730", fg="#dcdcdc", width=3,
              command=lambda: path.set(
                  filedialog.askopenfilename(filetypes=[("Executable", "*.exe")]) or path.get()
              )).pack(side="left", padx=(6, 0))

    preview = tk.Text(win, height=7, bg="#0b0d11", fg="#a9b1bb", relief="flat",
                      font=("Consolas", 9), cursor="arrow")
    preview.tag_config("dim",  foreground="#6f7783")
    preview.tag_config("old",  foreground="#ff7b72")
    preview.tag_config("new",  foreground="#7ee787")
    preview.tag_config("note", foreground="#8b9098")

    out = tk.Text(win, height=5, bg="#0e1014", fg="#a9b1bb", relief="flat",
                  font=("Consolas", 9))

    def refresh_preview(*_):
        preview.config(state="normal")
        preview.delete("1.0", "end")
        try:
            data, sites = scan(path.get())
        except Exception as e:
            preview.insert("end", f"cannot read file: {e}\n", "note")
            preview.config(state="disabled")
            return
        if not sites:
            preview.insert("end",
                           "no match for this build\n"
                           "the branch patterns are not there, nothing would be written\n",
                           "note")
            preview.config(state="disabled")
            return

        rows = byte_rows(data, sites)
        for off, before, after, changed, kind in rows:
            preview.insert("end", f"{off:#06x}  {kind:<15}", "dim")
            preview.insert("end", f"{before[0]:02X}", "old" if changed else "new")
            preview.insert("end", " " + " ".join(f"{x:02X}" for x in before[1:]) + "\n", "dim")
            preview.insert("end", " "*8 + " "*15 + "after   ", "dim")
            preview.insert("end", f"{after[0]:02X}", "new")
            preview.insert("end", " " + " ".join(f"{x:02X}" for x in after[1:]) + "\n", "dim")

        n = sum(1 for r in rows if r[3])
        preview.insert("end",
                       f"{n} byte{'s' if n != 1 else ''} will change" if n
                       else "already patched, nothing to write",
                       "note")
        preview.config(state="disabled")

    path.trace_add("write", refresh_preview)
    preview.pack(fill="x", padx=16, pady=(0, 6))
    out.pack(fill="both", expand=True, padx=16)

    def log(msg):
        out.insert("end", msg + "\n")
        out.see("end")

    def run(fn):
        def go():
            out.delete("1.0", "end")
            try:
                fn(path.get(), log)
            except PermissionError:
                log("needs administrator — relaunch the tool as admin")
            except Exception as e:
                log(f"error: {e}")
            refresh_preview()
        return go

    bar = tk.Frame(win, bg="#15171c")
    bar.pack(fill="x", padx=16, pady=12)
    tk.Button(bar, text="Apply patch",      command=run(apply_patch), width=14, pady=6,
              relief="flat", bg="#2d6cdf", fg="white").pack(side="left")
    tk.Button(bar, text="Restore original", command=run(restore),     width=16, pady=6,
              relief="flat", bg="#232730", fg="#dcdcdc").pack(side="left", padx=8)
    tk.Button(bar, text="Join Discord",     command=lambda: webbrowser.open(DISCORD),
              width=14, pady=6, relief="flat", bg="#5865F2", fg="white").pack(side="right")

    refresh_preview()
    win.mainloop()


def main():
    exe  = DEFAULT_EXE
    args = sys.argv[1:]
    if "--exe" in args:
        i   = args.index("--exe")
        exe = args[i+1]
        del args[i:i+2]

    if "--cli" in args:
        try:
            ok = restore(exe) if "--restore" in args else apply_patch(exe)
        except PermissionError:
            elevate()
            return 0
        except Exception as e:
            print(f"error: {e}")
            return 1
        return 0 if ok else 1

    if not is_admin():
        elevate()
    launch_gui(exe)
    return 0


if __name__ == "__main__":
    sys.exit(main())
