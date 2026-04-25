from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from secrets import token_bytes


DEPENDENCY_REQUIREMENTS = {
    "cryptography": "cryptography>=46.0.0",
    "dotenv": "python-dotenv>=1.2.0",
    "pyserpent": "pyserpent>=1.2.0",
}


def configure_stdio() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def ensure_runtime_dependencies() -> None:
    if os.getenv("SUPERENC_SKIP_AUTO_INSTALL") == "1":
        return

    missing_modules = [
        module_name
        for module_name in DEPENDENCY_REQUIREMENTS
        if importlib.util.find_spec(module_name) is None
    ]
    if not missing_modules:
        return

    requirements_file = Path(__file__).with_name("requirements.txt")
    command = [sys.executable, "-m", "pip", "install"]

    in_virtualenv = sys.prefix != getattr(sys, "base_prefix", sys.prefix)
    if not in_virtualenv:
        command.append("--user")

    if requirements_file.is_file():
        command.extend(["-r", str(requirements_file)])
        install_target = str(requirements_file)
    else:
        command.extend(DEPENDENCY_REQUIREMENTS[module_name] for module_name in missing_modules)
        install_target = ", ".join(missing_modules)

    print(f"Missing dependencies detected. Installing: {install_target}", file=sys.stderr)

    try:
        subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
        )
    except subprocess.CalledProcessError as exc:
        stderr = exc.stderr.strip() or "<empty>"
        stdout = exc.stdout.strip() or "<empty>"
        raise SystemExit(
            "Automatic dependency installation failed. "
            "Run `python -m pip install -r requirements.txt` manually.\n"
            f"stdout: {stdout}\n"
            f"stderr: {stderr}"
        ) from exc

    importlib.invalidate_caches()


configure_stdio()
ensure_runtime_dependencies()

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from dotenv import load_dotenv
from pyserpent import serpent_cbc_decrypt, serpent_cbc_encrypt


SERPENT_MAGIC = b"SE3SPT01"
CHACHA_MAGIC = b"SE3CHA01"
AES_MAGIC = b"SE3AES01"

DEFAULT_SCRYPT_N = 32768
DEFAULT_SCRYPT_R = 8
DEFAULT_SCRYPT_P = 1
DEFAULT_TARGET_LIST_FILENAME = "encrypt_targt.txt"

ENV_PASSWORDS = {
    "serpent": "LAYER1_SERPENT_PASSWORD",
    "chacha": "LAYER2_CHACHA_PASSWORD",
    "aes": "LAYER3_AES_PASSWORD",
}


class SuperEncryptError(Exception):
    """Base exception for user-facing failures."""


class EnvelopeError(SuperEncryptError):
    """Envelope parsing or authentication failure."""


@dataclass(frozen=True)
class PasswordSet:
    serpent: str
    chacha: str
    aes: str


@dataclass(frozen=True)
class KdfParams:
    n: int
    r: int
    p: int


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Encrypt or decrypt a file/folder through 3 layers: "
            "Serpent -> ChaCha20-Poly1305 -> AES-256-GCM. "
            f"If run without a command, it auto-decrypts targets from {DEFAULT_TARGET_LIST_FILENAME}."
        )
    )
    parser.add_argument(
        "--env",
        default=".env",
        help="Path to the .env file that contains the three passwords.",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow overwriting the output file or extracting into an existing directory.",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Create a 3-layer encrypted bundle.")
    encrypt_parser.add_argument("source", help="Source file or folder to package and encrypt.")
    encrypt_parser.add_argument("output", help="Output encrypted bundle path.")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a bundle and extract the packaged payload.")
    decrypt_parser.add_argument("bundle", help="Encrypted bundle produced by the encrypt command.")
    decrypt_parser.add_argument("output", help="Directory where the decrypted files will be extracted.")

    doctor_parser = subparsers.add_parser("doctor", help="Check passwords and KDF settings.")
    doctor_parser.add_argument(
        "--strict",
        action="store_true",
        help="Fail if the environment file or any password is missing.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    try:
        if not argv:
            handle_auto_decrypt()
            return 0

        parser = build_parser()
        args = parser.parse_args(argv)

        if args.command == "encrypt":
            handle_encrypt(args)
        elif args.command == "decrypt":
            handle_decrypt(args)
        elif args.command == "doctor":
            handle_doctor(args)
        else:
            raise SuperEncryptError(f"Unsupported command: {args.command}")
    except SuperEncryptError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    return 0


def handle_encrypt(args: argparse.Namespace) -> None:
    env_path = Path(args.env).resolve()
    source_path = Path(args.source).resolve()
    output_path = Path(args.output).resolve()

    ensure_source_exists(source_path)
    ensure_output_file_is_writable(output_path, overwrite=args.overwrite)

    passwords = load_passwords(env_path)
    kdf_params = load_kdf_params()

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="super_encrypt_") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        package_path = temp_dir / "payload.tar"
        layer1_serpent = temp_dir / "layer1.serpent"
        layer2_chacha = temp_dir / "layer2.chacha"

        create_tar_package(source_path, package_path)
        encrypt_with_serpent(package_path, layer1_serpent, passwords.serpent, kdf_params)
        encrypt_with_chacha(layer1_serpent, layer2_chacha, passwords.chacha, kdf_params)
        encrypt_with_aes(layer2_chacha, output_path, passwords.aes, kdf_params)

    print(f"Encrypted bundle written to: {output_path}")


def handle_decrypt(args: argparse.Namespace) -> None:
    env_path = Path(args.env).resolve()
    bundle_path = Path(args.bundle).resolve()
    output_dir = Path(args.output).resolve()

    passwords = load_passwords(env_path)
    decrypt_bundle_to_directory(bundle_path, output_dir, passwords, overwrite=args.overwrite)
    print(f"Decrypted files extracted to: {output_dir}")


def handle_doctor(args: argparse.Namespace) -> None:
    env_path = Path(args.env).resolve()
    status: dict[str, object] = {
        "env_file": str(env_path),
        "env_file_exists": env_path.is_file(),
        "passwords": {},
    }

    status["env_loaded"] = load_env_file_if_present(env_path)
    status["kdf"] = load_kdf_params().__dict__
    for key, env_name in ENV_PASSWORDS.items():
        value = os.getenv(env_name)
        status["passwords"][key] = bool(value)

    print(json.dumps(status, indent=2))

    if args.strict:
        missing_passwords = [
            env_name
            for env_name in ENV_PASSWORDS.values()
            if not os.getenv(env_name)
        ]
        if missing_passwords:
            joined = ", ".join(missing_passwords)
            if status["env_file_exists"]:
                raise SuperEncryptError(f"Missing required passwords: {joined}")
            raise SuperEncryptError(
                f".env file not found at {env_path} and required environment variables are missing: {joined}"
            )


def handle_auto_decrypt(
    *,
    env_path: Path | None = None,
    target_list_path: Path | None = None,
    project_root: Path | None = None,
) -> None:
    resolved_project_root = (project_root or Path.cwd()).resolve()
    resolved_env_path = resolve_env_path(env_path, resolved_project_root)
    resolved_target_list = resolve_target_list_path(target_list_path, resolved_project_root)
    passwords = load_passwords(resolved_env_path)
    target_paths = read_target_list(resolved_target_list)

    if not target_paths:
        raise SuperEncryptError(f"No encrypted targets were found inside {resolved_target_list}")

    print(f"Auto decrypt mode using target list: {resolved_target_list}")
    for bundle_path in target_paths:
        resolved_bundle = resolve_target_entry(bundle_path, resolved_target_list.parent, resolved_project_root)
        print(f"Decrypting target: {resolved_bundle}")
        decrypt_bundle_to_directory(
            resolved_bundle,
            resolved_project_root,
            passwords,
            overwrite=True,
        )
    print(f"Auto decrypt mode finished. Restored files into: {resolved_project_root}")


def resolve_env_path(env_path: Path | None, project_root: Path) -> Path:
    if env_path is not None:
        return env_path.resolve()

    cwd_env = project_root / ".env"
    if cwd_env.is_file():
        return cwd_env.resolve()

    return Path(__file__).with_name(".env").resolve()


def resolve_target_list_path(target_list_path: Path | None, project_root: Path) -> Path:
    if target_list_path is not None:
        return target_list_path.resolve()

    cwd_target_list = project_root / DEFAULT_TARGET_LIST_FILENAME
    if cwd_target_list.is_file():
        return cwd_target_list.resolve()

    script_target_list = Path(__file__).with_name(DEFAULT_TARGET_LIST_FILENAME).resolve()
    if script_target_list.is_file():
        return script_target_list

    raise SuperEncryptError(
        f"{DEFAULT_TARGET_LIST_FILENAME} was not found in {project_root} or next to the script."
    )


def load_env_file_if_present(env_path: Path) -> bool:
    if not env_path.is_file():
        return False

    load_dotenv(dotenv_path=env_path, override=True)
    return True


def load_passwords(env_path: Path) -> PasswordSet:
    env_loaded = load_env_file_if_present(env_path)

    resolved: dict[str, str] = {}
    missing: list[str] = []

    for key, env_name in ENV_PASSWORDS.items():
        value = os.getenv(env_name)
        if value is None or value == "":
            missing.append(env_name)
        else:
            resolved[key] = value

    if missing:
        missing_joined = ", ".join(missing)
        if env_loaded:
            raise SuperEncryptError(f"Missing required secrets in {env_path}: {missing_joined}")
        raise SuperEncryptError(
            f"Required secrets are missing. "
            f"Provide them in {env_path} or as environment variables: {missing_joined}"
        )

    return PasswordSet(
        serpent=resolved["serpent"],
        chacha=resolved["chacha"],
        aes=resolved["aes"],
    )


def load_kdf_params() -> KdfParams:
    n = int(os.getenv("SUPERENC_SCRYPT_N", DEFAULT_SCRYPT_N))
    r = int(os.getenv("SUPERENC_SCRYPT_R", DEFAULT_SCRYPT_R))
    p = int(os.getenv("SUPERENC_SCRYPT_P", DEFAULT_SCRYPT_P))

    if n < 2 or n & (n - 1) != 0:
        raise SuperEncryptError("SUPERENC_SCRYPT_N must be a power of two greater than 1.")
    if r <= 0 or p <= 0:
        raise SuperEncryptError("SUPERENC_SCRYPT_R and SUPERENC_SCRYPT_P must be positive integers.")

    return KdfParams(n=n, r=r, p=p)


def ensure_source_exists(source_path: Path) -> None:
    if not source_path.exists():
        raise SuperEncryptError(f"Source path not found: {source_path}")


def ensure_output_file_is_writable(output_path: Path, *, overwrite: bool) -> None:
    if output_path.exists() and output_path.is_dir():
        raise SuperEncryptError(f"Output path is a directory, expected a file: {output_path}")
    if output_path.exists() and not overwrite:
        raise SuperEncryptError(
            f"Output file already exists: {output_path}. Use --overwrite to replace it."
        )


def ensure_output_directory_is_ready(output_dir: Path, *, overwrite: bool) -> None:
    if output_dir.exists() and output_dir.is_file():
        raise SuperEncryptError(f"Output path is a file, expected a directory: {output_dir}")
    if output_dir.exists() and any(output_dir.iterdir()) and not overwrite:
        raise SuperEncryptError(
            f"Output directory is not empty: {output_dir}. Use --overwrite to extract into it."
        )


def create_tar_package(source_path: Path, package_path: Path, *, base_dir: Path | None = None) -> None:
    package_path.parent.mkdir(parents=True, exist_ok=True)

    resolved_base_dir = (base_dir or Path.cwd()).resolve()
    try:
        arcname_path = source_path.relative_to(resolved_base_dir)
        if str(arcname_path) == ".":
            arcname_path = Path(source_path.name)
    except ValueError:
        arcname_path = Path(source_path.name)

    with tarfile.open(package_path, mode="w", format=tarfile.PAX_FORMAT) as archive:
        archive.add(source_path, arcname=str(arcname_path), recursive=True)


def decrypt_bundle_to_directory(
    bundle_path: Path,
    output_dir: Path,
    passwords: PasswordSet,
    *,
    overwrite: bool,
) -> None:
    if not bundle_path.is_file():
        raise SuperEncryptError(f"Encrypted bundle not found: {bundle_path}")

    ensure_output_directory_is_ready(output_dir, overwrite=overwrite)

    with tempfile.TemporaryDirectory(prefix="super_decrypt_") as temp_dir_name:
        temp_dir = Path(temp_dir_name)
        layer2_chacha = temp_dir / "layer2.chacha"
        layer1_serpent = temp_dir / "layer1.serpent"
        package_path = temp_dir / "payload.tar"

        decrypt_with_aes(bundle_path, layer2_chacha, passwords.aes)
        decrypt_with_chacha(layer2_chacha, layer1_serpent, passwords.chacha)
        decrypt_with_serpent(layer1_serpent, package_path, passwords.serpent)
        extract_tar_package(package_path, output_dir, overwrite=overwrite)


def read_target_list(target_list_path: Path) -> list[str]:
    entries: list[str] = []
    for raw_line in target_list_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if len(line) >= 2 and line[0] == line[-1] and line[0] in {"'", '"'}:
            line = line[1:-1]
        entries.append(line)
    return entries


def resolve_target_entry(entry: str, target_list_dir: Path, project_root: Path) -> Path:
    candidate = Path(entry)
    if candidate.is_absolute():
        return candidate.resolve()

    primary = (project_root / candidate).resolve()
    if primary.exists():
        return primary

    return (target_list_dir / candidate).resolve()


def extract_tar_package(package_path: Path, output_dir: Path, *, overwrite: bool) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    base_dir = output_dir.resolve()

    with tarfile.open(package_path, mode="r") as archive:
        members = archive.getmembers()
        for member in members:
            if member.issym() or member.islnk():
                raise SuperEncryptError("Links inside the packaged payload are not supported.")

            member_path = Path(member.name)
            target_path = (output_dir / member.name).resolve()
            if not is_within_directory(base_dir, target_path):
                raise SuperEncryptError(f"Unsafe path inside packaged payload: {member.name}")
            if target_path.exists() and not overwrite:
                raise SuperEncryptError(
                    f"Refusing to overwrite existing extracted path: {target_path}. "
                    "Use --overwrite to allow replacement."
                )

        archive.extractall(output_dir, filter="data")


def is_within_directory(base_dir: Path, target_path: Path) -> bool:
    try:
        target_path.relative_to(base_dir)
    except ValueError:
        return False
    return True


def encrypt_with_serpent(
    input_path: Path,
    output_path: Path,
    password: str,
    kdf_params: KdfParams,
) -> None:
    plaintext = input_path.read_bytes()
    salt = token_bytes(16)
    iv = token_bytes(16)
    key_material = derive_key(password, salt, 64, kdf_params)
    encryption_key = key_material[:32]
    mac_key = key_material[32:]

    ciphertext = serpent_cbc_encrypt(encryption_key, plaintext, iv=iv)[16:]
    header = {
        "algorithm": "serpent-cbc+hmac-sha256",
        "version": 1,
        "kdf": kdf_dict(kdf_params, salt),
        "iv": iv.hex(),
        "plaintext_size": len(plaintext),
    }

    prefix = build_prefix(SERPENT_MAGIC, header)
    mac = hmac.new(mac_key, prefix + ciphertext, hashlib.sha256).digest()
    output_path.write_bytes(prefix + ciphertext + mac)


def decrypt_with_serpent(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    blob = input_path.read_bytes()
    header, ciphertext, mac, prefix = parse_envelope(blob, SERPENT_MAGIC, trailer_size=32)
    salt = bytes.fromhex(header["kdf"]["salt"])
    iv = bytes.fromhex(header["iv"])
    stored_params = read_kdf_from_header(header)

    key_material = derive_key(password, salt, 64, stored_params)
    encryption_key = key_material[:32]
    mac_key = key_material[32:]
    expected_mac = hmac.new(mac_key, prefix + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expected_mac):
        raise EnvelopeError("Serpent layer authentication failed. Password 1 may be wrong or data was modified.")

    try:
        plaintext = serpent_cbc_decrypt(encryption_key, iv + ciphertext)
    except Exception as exc:  # pragma: no cover
        raise EnvelopeError("Serpent layer decryption failed.") from exc

    if len(plaintext) != header["plaintext_size"]:
        raise EnvelopeError("Serpent layer size check failed.")

    output_path.write_bytes(plaintext)


def encrypt_with_chacha(
    input_path: Path,
    output_path: Path,
    password: str,
    kdf_params: KdfParams,
) -> None:
    plaintext = input_path.read_bytes()
    salt = token_bytes(16)
    nonce = token_bytes(12)
    key = derive_key(password, salt, 32, kdf_params)

    header = {
        "algorithm": "chacha20-poly1305",
        "version": 1,
        "kdf": kdf_dict(kdf_params, salt),
        "nonce": nonce.hex(),
        "plaintext_size": len(plaintext),
    }

    prefix = build_prefix(CHACHA_MAGIC, header)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, prefix)
    output_path.write_bytes(prefix + ciphertext)


def decrypt_with_chacha(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    blob = input_path.read_bytes()
    header, ciphertext, _unused, prefix = parse_envelope(blob, CHACHA_MAGIC)
    salt = bytes.fromhex(header["kdf"]["salt"])
    nonce = bytes.fromhex(header["nonce"])
    stored_params = read_kdf_from_header(header)

    key = derive_key(password, salt, 32, stored_params)
    try:
        plaintext = ChaCha20Poly1305(key).decrypt(nonce, ciphertext, prefix)
    except Exception as exc:  # pragma: no cover
        raise EnvelopeError("ChaCha20-Poly1305 layer authentication failed.") from exc

    if len(plaintext) != header["plaintext_size"]:
        raise EnvelopeError("ChaCha20 layer size check failed.")

    output_path.write_bytes(plaintext)


def encrypt_with_aes(
    input_path: Path,
    output_path: Path,
    password: str,
    kdf_params: KdfParams,
) -> None:
    plaintext = input_path.read_bytes()
    salt = token_bytes(16)
    nonce = token_bytes(12)
    key = derive_key(password, salt, 32, kdf_params)

    header = {
        "algorithm": "aes-256-gcm",
        "version": 1,
        "kdf": kdf_dict(kdf_params, salt),
        "nonce": nonce.hex(),
        "plaintext_size": len(plaintext),
    }

    prefix = build_prefix(AES_MAGIC, header)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, prefix)
    output_path.write_bytes(prefix + ciphertext)


def decrypt_with_aes(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    blob = input_path.read_bytes()
    header, ciphertext, _unused, prefix = parse_envelope(blob, AES_MAGIC)
    salt = bytes.fromhex(header["kdf"]["salt"])
    nonce = bytes.fromhex(header["nonce"])
    stored_params = read_kdf_from_header(header)

    key = derive_key(password, salt, 32, stored_params)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, prefix)
    except Exception as exc:  # pragma: no cover
        raise EnvelopeError("AES-256-GCM layer authentication failed.") from exc

    if len(plaintext) != header["plaintext_size"]:
        raise EnvelopeError("AES layer size check failed.")

    output_path.write_bytes(plaintext)


def derive_key(password: str, salt: bytes, length: int, kdf_params: KdfParams) -> bytes:
    maxmem = max(1024 * 1024 * 1024, 256 * kdf_params.n * kdf_params.r * kdf_params.p)
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=kdf_params.n,
        r=kdf_params.r,
        p=kdf_params.p,
        dklen=length,
        maxmem=maxmem,
    )


def kdf_dict(kdf_params: KdfParams, salt: bytes) -> dict[str, int | str]:
    return {
        "name": "scrypt",
        "n": kdf_params.n,
        "r": kdf_params.r,
        "p": kdf_params.p,
        "salt": salt.hex(),
    }


def read_kdf_from_header(header: dict[str, object]) -> KdfParams:
    kdf_section = header["kdf"]
    if not isinstance(kdf_section, dict):
        raise EnvelopeError("Invalid KDF section.")
    try:
        return KdfParams(
            n=int(kdf_section["n"]),
            r=int(kdf_section["r"]),
            p=int(kdf_section["p"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise EnvelopeError("Invalid KDF parameters in header.") from exc


def build_prefix(magic: bytes, header: dict[str, object]) -> bytes:
    header_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return magic + len(header_bytes).to_bytes(4, "big") + header_bytes


def parse_envelope(
    blob: bytes,
    expected_magic: bytes,
    trailer_size: int = 0,
) -> tuple[dict[str, object], bytes, bytes, bytes]:
    if len(blob) < len(expected_magic) + 4 + trailer_size:
        raise EnvelopeError("Encrypted blob is too short.")

    if blob[: len(expected_magic)] != expected_magic:
        raise EnvelopeError("Unexpected file signature or wrong layer order.")

    header_length_start = len(expected_magic)
    header_length_end = header_length_start + 4
    header_length = int.from_bytes(blob[header_length_start:header_length_end], "big")
    header_start = header_length_end
    header_end = header_start + header_length

    if header_end + trailer_size > len(blob):
        raise EnvelopeError("Envelope header is truncated.")

    header_bytes = blob[header_start:header_end]
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise EnvelopeError("Envelope header is not valid JSON.") from exc

    payload_end = len(blob) - trailer_size if trailer_size else len(blob)
    payload = blob[header_end:payload_end]
    trailer = blob[payload_end:]
    prefix = blob[:header_end]

    return header, payload, trailer, prefix


if __name__ == "__main__":
    raise SystemExit(main())
