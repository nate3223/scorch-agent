from dotenv import load_dotenv
import os
import subprocess
import shutil
from pathlib import Path
import platform

ROOT = Path(__file__).resolve().parent
BUILDROOT = ROOT / "build"

def setup_env():
	load_dotenv()
	env = os.environ.copy()

	if platform.system() == "Windows":
		env = setup_msvc_env(env)

	return env

def setup_msvc_env(env):
	vswhere = (
		Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))
		/ "Microsoft Visual Studio/Installer/vswhere.exe"
	)

	if not vswhere.exists():
		raise RuntimeError("Could not find vswhere.exe")

	vs_dir = subprocess.check_output(
		[str(vswhere), "-latest", "-property", "installationPath"], text=True
	).strip()

	vcvars = Path(vs_dir) / "VC/Auxiliary/Build/vcvarsall.bat"
	if not vcvars.exists():
		raise RuntimeError(f"Could not find vcvarsall.bat at {vcvars}")

	env_output = subprocess.check_output(f'"{vcvars}" x64 && set', shell=True, text=True)
	print("Adding extra environment variables:")
	for line in env_output.splitlines():
		if "=" in line:
			print(line)
			k, v = line.split("=", 1)
			env[k] = v

	return env

if __name__ == "__main__":
	env = setup_env()
	BUILDROOT.mkdir(exist_ok=True)

	configure_args = []
	build_args = []

	if shutil.which("ninja"):
		configure_args.extend(["-G", "Ninja"])
	else:
		build_args.extend(["-j4"])

	vcpkg_root = Path(os.environ.get("VCPKG_ROOT", ""))
	toolchain = vcpkg_root / "scripts" / "buildsystems" / "vcpkg.cmake"
	if toolchain.exists():
		configure_args.append(f"-DCMAKE_TOOLCHAIN_FILE={toolchain}")

	configure_command = ["cmake", "-S", str(ROOT), "-B", str(BUILDROOT)] + configure_args
	print("Running configure:", configure_command)
	subprocess.run(configure_command, check=True, env=env)

	build_command = ["cmake", "--build", str(BUILDROOT)] + build_args
	print("=" * 20)
	print("Running build:", build_command)
	subprocess.run(build_command, check=True, env=env)

