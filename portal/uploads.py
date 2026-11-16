"""Assignment upload validation -- mitigates T1204.002 (User Execution:
Malicious File), where a lecturer opens a hostile file a "student" uploaded.

Documented upload policy (ASVS 5.1.1):
  permitted types .... PDF (.pdf) and Word (.docx) only
  max size ........... 10 MB per file, one file per assignment per student
  .docx unpacked ..... <= 100 MB, <= 2000 entries, no macros
  storage ............ outside the web root, random server-chosen name
"""
import hashlib
import io
import os
import re
import shutil
import subprocess
import uuid
import zipfile

MAX_BYTES = 10 * 1024 * 1024
MAX_UNPACKED = 100 * 1024 * 1024
MAX_ZIP_ENTRIES = 2000
ALLOWED_EXT = {"pdf", "docx"}
MIME = {
    "pdf": "application/pdf",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
}
_PDF_ACTIVE = re.compile(rb"/(JavaScript|JS|Launch)\b")


class UploadRejected(Exception):
    """Message is safe to show to the user."""


def display_name(filename):
    """Sanitised copy of the client's filename, used for display only --
    it is never used to build a path (ASVS 5.3.2)."""
    name = os.path.basename((filename or "").replace("\\", "/"))
    name = re.sub(r"[^A-Za-z0-9._ -]", "_", name).strip(" .")
    return name[:100] or "file"


def validate(filename, data):
    """Return the validated extension or raise UploadRejected."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in (filename or "") else ""
    if ext not in ALLOWED_EXT:
        raise UploadRejected("Only PDF (.pdf) and Word (.docx) files are accepted.")
    if len(data) == 0:
        raise UploadRejected("That file is empty.")
    if len(data) > MAX_BYTES:
        raise UploadRejected("That file is larger than the 10 MB limit.")

    # The extension is attacker-controlled, so check the content matches it.
    if ext == "pdf":
        if not data.startswith(b"%PDF-"):
            raise UploadRejected("That file is not a valid PDF.")
        if _PDF_ACTIVE.search(data):
            raise UploadRejected("PDFs containing scripts or launch actions are not accepted.")
    else:
        _validate_docx(data)
    return ext


def _validate_docx(data):
    bad = UploadRejected("That file is not a valid Word (.docx) document.")
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        raise bad from None
    infos = zf.infolist()
    # Zip-bomb guard: inspect declared sizes *before* decompressing anything.
    if len(infos) > MAX_ZIP_ENTRIES or sum(i.file_size for i in infos) > MAX_UNPACKED:
        raise UploadRejected("That document is too large when unpacked.")
    names = {i.filename for i in infos}
    if "[Content_Types].xml" not in names or "word/document.xml" not in names:
        raise bad
    if any(n.startswith("/") or ".." in n.split("/") for n in names):
        raise bad
    content_types = zf.read("[Content_Types].xml").lower()
    if any(n.lower().endswith("vbaproject.bin") for n in names) or b"macroenabled" in content_types:
        raise UploadRejected("Documents containing macros are not accepted.")


def malware_scan(path):
    """Scan with ClamAV when it is installed (ASVS 5.4.3).

    Returns 'clean' or 'unscanned'; raises UploadRejected on a detection.
    'unscanned' is stored and shown to the lecturer so the residual risk is
    visible rather than silently ignored."""
    scanner = shutil.which("clamdscan") or shutil.which("clamscan")
    if not scanner:
        return "unscanned"
    result = subprocess.run([scanner, "--no-summary", path], capture_output=True, timeout=60)
    if result.returncode == 1:
        raise UploadRejected("That file was blocked by the malware scanner.")
    return "clean" if result.returncode == 0 else "unscanned"


def store(upload_dir, data):
    """Write under a random name with no extension so the file can never be
    executed or content-sniffed from disk. Returns (stored_name, sha256)."""
    stored = uuid.uuid4().hex
    path = os.path.join(upload_dir, stored)
    with open(path, "xb") as fh:
        fh.write(data)
    os.chmod(path, 0o600)
    return stored, hashlib.sha256(data).hexdigest()
