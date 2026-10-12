"""Helpers for the PoC.

  python -I tarutil.py mk-restore            -> base64 tar of a "previous chat" workspace
  python -I tarutil.py dump <snapshot.json>  -> list + print every file in a /snapshot body
  python -I tarutil.py summary <snapshot.json> -> one-line summary (members, sha256 of big files)
"""
import base64
import hashlib
import io
import json
import sys
import tarfile


def mk_restore():
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode="w") as t:
        files = {
            "notes/medical_record.txt": b"Patient: Jane Doe\nDOB: 1980-02-03\nDiagnosis: <confidential>\n",
            "prev_session/model_notes.md": b"# notes from an earlier turn of this chat\nuser asked to analyse their payroll export\n",
        }
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o644
            t.addfile(ti, io.BytesIO(data))
    sys.stdout.write(base64.b64encode(b.getvalue()).decode())


def load(path):
    with open(path) as f:
        d = json.load(f)
    raw = base64.b64decode(d["tar"])
    return tarfile.open(fileobj=io.BytesIO(raw))


def dump(path):
    t = load(path)
    for m in t.getmembers():
        if m.isdir():
            print(f"[dir ] {m.name}")
            continue
        data = t.extractfile(m).read()
        print(f"[file] {m.name} ({len(data)} bytes, uid={m.uid})")
        if len(data) <= 4096:
            for line in data.decode(errors="replace").splitlines():
                print(f"         | {line}")
        else:
            print(f"         | sha256={hashlib.sha256(data).hexdigest()}")


def summary(path):
    t = load(path)
    out = []
    for m in t.getmembers():
        if m.isfile():
            data = t.extractfile(m).read()
            out.append(f"{m.name}:{len(data)}B:{hashlib.sha256(data).hexdigest()[:16]}")
    print(f"{len(out)} files: " + ", ".join(out))


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "mk-restore":
        mk_restore()
    elif cmd == "dump":
        dump(sys.argv[2])
    elif cmd == "summary":
        summary(sys.argv[2])
    else:
        raise SystemExit("unknown command")
