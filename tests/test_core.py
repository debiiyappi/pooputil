import os
import zipfile
from pathlib import Path

import pytest

from pooputil import core

PW = b"correct horse battery staple"


def _roundtrip(tmp_path, name="data.bin", data=b"payload"):
    src = tmp_path / name
    src.write_bytes(data)
    poop = core.encrypt_target(str(src), PW)
    assert poop == str(src) + ".poop"
    assert not src.exists()
    restored = core.decrypt_target(poop, PW)
    assert Path(restored).read_bytes() == data
    assert not Path(poop).exists()


def test_roundtrip_small(tmp_path):
    _roundtrip(tmp_path, data=b"hello world\n" * 500)


def test_roundtrip_empty_file(tmp_path):
    _roundtrip(tmp_path, data=b"")


def test_roundtrip_one_byte(tmp_path):
    _roundtrip(tmp_path, data=b"\x00")


def test_roundtrip_random_binary(tmp_path):
    _roundtrip(tmp_path, data=os.urandom(64 * 1024 + 123))


def test_roundtrip_large(tmp_path):
    _roundtrip(tmp_path, data=os.urandom(5 * 1024 * 1024))


def test_roundtrip_unicode_filename(tmp_path):
    _roundtrip(tmp_path, name="täst-文件-🙂.pdf", data=b"unicode payload")


def test_encrypted_output_is_not_plaintext(tmp_path):
    src = tmp_path / "f.txt"
    src.write_bytes(b"TOP SECRET")
    poop = Path(core.encrypt_target(str(src), PW))
    assert b"TOP SECRET" not in poop.read_bytes()


def test_folder_roundtrip_nested(tmp_path):
    folder = tmp_path / "proj"
    (folder / "src" / "pkg").mkdir(parents=True)
    (folder / "src" / "pkg" / "mod.py").write_text("x = 1\n")
    (folder / "src" / "main.py").write_text("print('hi')\n")
    (folder / "README.md").write_text("# proj\n")
    (folder / ".hidden").write_text("dotfile")
    (folder / "src" / "empty.txt").touch()

    poop = core.encrypt_target(str(folder), PW)
    assert not folder.exists()

    restored = core.decrypt_target(poop, PW)
    root = Path(restored)
    assert root.is_dir()
    assert root.name == "proj"
    assert (root / "src" / "pkg" / "mod.py").read_text() == "x = 1\n"
    assert (root / "src" / "main.py").read_text() == "print('hi')\n"
    assert (root / "README.md").read_text() == "# proj\n"
    assert (root / ".hidden").read_text() == "dotfile"
    assert (root / "src" / "empty.txt").exists()
    assert not (tmp_path / "proj.zip").exists()
    assert not Path(poop).exists()


def test_wrong_password(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"secret")
    poop = core.encrypt_target(str(src), PW)
    with pytest.raises(core.InvalidPoopFile):
        core.decrypt_target(poop, b"wrong password")
    assert Path(poop).exists()
    assert not (tmp_path / "f.bin").exists()
    assert not list(tmp_path.glob("*.tmp"))


def test_corrupted_tag(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"data")
    poop = Path(core.encrypt_target(str(src), PW))
    raw = bytearray(poop.read_bytes())
    raw[core.TAG_OFFSET] ^= 0xFF
    poop.write_bytes(bytes(raw))
    with pytest.raises(core.InvalidPoopFile):
        core.decrypt_target(str(poop), PW)
    assert poop.exists()


def test_corrupted_magic(tmp_path):
    poop = tmp_path / "x.poop"
    poop.write_bytes(b"NOTP" + os.urandom(46))
    with pytest.raises(core.InvalidPoopFile):
        core.decrypt_target(str(poop), PW)
    assert poop.exists()


def test_unsupported_version(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"x")
    poop = Path(core.encrypt_target(str(src), PW))
    raw = bytearray(poop.read_bytes())
    raw[len(core.MAGIC)] = 0x02
    poop.write_bytes(bytes(raw))
    with pytest.raises(core.InvalidPoopFile):
        core.decrypt_target(str(poop), PW)


def test_truncated_file(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"data" * 4096)
    poop = Path(core.encrypt_target(str(src), PW))
    raw = poop.read_bytes()
    poop.write_bytes(raw[: len(raw) // 2])
    with pytest.raises(core.InvalidPoopFile):
        core.decrypt_target(str(poop), PW)


def test_garbage_input_never_crashes(tmp_path):
    for i in range(100):
        f = tmp_path / f"garbage_{i}.poop"
        f.write_bytes(os.urandom(os.urandom(1)[0]))
        with pytest.raises(core.InvalidPoopFile):
            core.decrypt_target(str(f), PW)
        assert not list(tmp_path.glob("*.tmp"))


def test_poop_header_format(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"payload")
    poop = Path(core.encrypt_target(str(src), PW))
    head = poop.read_bytes()[: core.HEADER_SIZE]
    assert head[:4] == b"POOP"
    assert head[4:5] == b"\x01"
    assert head[5:6] == core.TYPE_FILE
    assert len(head) == core.HEADER_SIZE


def test_encrypt_refuses_existing_output(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"data")
    existing = tmp_path / "f.bin.poop"
    existing.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        core.encrypt_target(str(src), PW)
    assert existing.read_bytes() == b"precious"
    assert src.exists()


def test_encrypt_force_overwrites(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"new data")
    (tmp_path / "f.bin.poop").write_bytes(b"old")
    poop = core.encrypt_target(str(src), PW, force=True)
    assert Path(poop).read_bytes() != b"old"
    assert not src.exists()


def test_stale_temp_blocks_encrypt(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"data")
    stale = tmp_path / "f.bin.poop.tmp"
    stale.write_bytes(b"stale")
    with pytest.raises(FileExistsError):
        core.encrypt_target(str(src), PW)
    assert stale.read_bytes() == b"stale"
    assert src.exists()


def test_decrypt_refuses_existing_output(tmp_path):
    src = tmp_path / "f.bin"
    src.write_bytes(b"data")
    poop = Path(core.encrypt_target(str(src), PW))
    (tmp_path / "f.bin").write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        core.decrypt_target(str(poop), PW)
    assert (tmp_path / "f.bin").read_bytes() == b"precious"
    assert poop.exists()


def test_decrypt_folder_refuses_existing_dir(tmp_path):
    folder = tmp_path / "proj"
    folder.mkdir()
    (folder / "a.txt").write_text("a")
    poop = Path(core.encrypt_target(str(folder), PW))
    assert not folder.exists()
    folder.mkdir()
    (folder / "precious.txt").write_text("keep")
    with pytest.raises(FileExistsError):
        core.decrypt_target(str(poop), PW)
    assert (folder / "precious.txt").read_text() == "keep"
    assert poop.exists()


def test_is_safe_path_home_allowed(tmp_path):
    assert core.is_safe_path(str(tmp_path / "subdir" / "file.txt"))


def test_is_safe_path_blocks_roots_and_system_dirs(tmp_path):
    assert not core.is_safe_path(str(tmp_path.anchor))
    if os.name == "nt":
        assert not core.is_safe_path(r"C:\Windows")
        assert not core.is_safe_path(r"C:\Windows\System32\drivers\etc\hosts")
        assert not core.is_safe_path(r"C:\Program Files")
    else:
        assert not core.is_safe_path("/")
        assert not core.is_safe_path("/etc")
        assert not core.is_safe_path("/etc/hosts")
        assert not core.is_safe_path("/usr/bin")


def _symlink_or_skip(link: Path, target: Path) -> None:
    if not hasattr(os, "symlink"):
        pytest.skip("symlinks not supported")
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("cannot create symlinks here")


def test_symlink_target_rejected(tmp_path):
    target = tmp_path / "real.bin"
    target.write_bytes(b"real")
    link = tmp_path / "link.bin"
    _symlink_or_skip(link, target)
    with pytest.raises(ValueError):
        core.encrypt_target(str(link), PW)
    assert target.read_bytes() == b"real"


def test_secure_delete_unlinks_symlink_not_target(tmp_path):
    target = tmp_path / "real.bin"
    target.write_bytes(b"real")
    link = tmp_path / "link.bin"
    _symlink_or_skip(link, target)
    core.secure_delete(str(link))
    assert not link.exists()
    assert target.read_bytes() == b"real"


def test_extract_zip_slip_rejected(tmp_path):
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("../evil.txt", b"evil")
    out = tmp_path / "out"
    with pytest.raises(core.InvalidPoopFile):
        core._extract_zip(str(zpath), str(out))
    assert not (tmp_path / "evil.txt").exists()


def test_extract_zip_symlink_rejected(tmp_path):
    zpath = tmp_path / "link.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        info = zipfile.ZipInfo("pwn")
        info.create_system = 3
        info.external_attr = (0o120777 << 16) | 0o777
        zf.writestr(info, b"/etc/passwd")
    out = tmp_path / "out"
    with pytest.raises(core.InvalidPoopFile):
        core._extract_zip(str(zpath), str(out))


def test_extract_zip_bomb_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(core, "MAX_EXTRACT_SIZE", 1000)
    zpath = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("payload.bin", os.urandom(5000))
    out = tmp_path / "out"
    with pytest.raises(core.InvalidPoopFile):
        core._extract_zip(str(zpath), str(out))


def test_secure_delete_removes_file(tmp_path):
    f = tmp_path / "x.bin"
    f.write_bytes(b"data")
    core.secure_delete(str(f))
    assert not f.exists()
