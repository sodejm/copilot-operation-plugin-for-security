# Isolated service runtime

This image contains the Python runtime, pinned cryptography and EVTX dependencies for
the [strict laboratory gate](../../docs/SERVICE_LABORATORY.md). Source code and
fixture evidence are mounted separately as a verified read-only snapshot.

Use the official full CPython 3.14.6 image pinned below, which includes Git
2.47.3 for the disposable credential-history exercise. The build records the
Git executable hash in a root-owned manifest before dropping privileges. The
scanner stages and verifies that pinned executable before enumerating blobs.
For Linux amd64, download the wheels into a disposable build directory:

```console
build_dir=$(mktemp -d)
cp laboratories/service-runtime/Dockerfile laboratories/service-runtime/requirements.txt laboratories/service-runtime/pin_runtime.py "$build_dir/"
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 --max-filesize 65536 \
  --output "$build_dir/hexdump-3.3.zip" \
  https://files.pythonhosted.org/packages/55/b3/279b1d57fa3681725d0db8820405cdcb4e62a9239c205e4ceac4391c78e4/hexdump-3.3.zip
python laboratories/service-runtime/build_hexdump_wheel.py "$build_dir/hexdump-3.3.zip" "$build_dir/wheels"
python -m pip download --index-url https://pypi.org/simple --only-binary=:all: \
  --require-hashes --find-links "$build_dir/wheels" \
  --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64 \
  --python-version 314 --implementation cp --abi cp314 \
  --dest "$build_dir/wheels" -r laboratories/service-runtime/requirements.txt
docker pull python:3.14.6@sha256:51570a50616289f78f340811c34ca4384985f9e891819cbe7620f738d6ca8525
docker build --network none --pull=false \
  --build-arg BASE_IMAGE=python:3.14.6@sha256:51570a50616289f78f340811c34ca4384985f9e891819cbe7620f738d6ca8525 \
  --iidfile "$build_dir/image.id" "$build_dir"
make check-laboratory LABORATORY_ARGS="--runtime docker --image $(cat "$build_dir/image.id")"
```

On Linux arm64, replace both platform values with `manylinux_2_28_aarch64` and
`manylinux2014_aarch64`. The hashes cover only these two architectures and
CPython 3.14. Other runtimes need a separately reviewed lock. Network access is
used only to obtain prerequisites; the build and assessment run without it.
Remove the disposable build directory after retaining the image ID and result.

The [python-evtx 0.8.1](https://pypi.org/project/python-evtx/0.8.1/) wheel
requires [hexdump 3.3](https://pypi.org/project/hexdump/3.3/), whose public-domain
release has no wheel. The repository builder verifies the source archive's
SHA-256, copies only its reviewed `hexdump.py` module, and produces a deterministic
wheel without executing upstream build scripts. The requirements file pins that
wheel's hash as well as the parser wheel. Any source or packaging change therefore
requires review and an updated pin. These prerequisites are mandatory for the
binary EVTX correction case; missing or mismatched versions fail the laboratory gate.

The Docker daemon must be able to bind-mount the temporary source snapshot.
With a macOS VM runtime, set `TMPDIR` to a disposable directory inside an
existing host share before invoking the gate. The launcher copies only its
allowlisted runtime and synthetic fixtures into that directory, mounts them
read-only, and removes the snapshot afterward. A directory outside the VM's
shares causes `container-create` to fail before any service activity.

The `isolated-service-laboratory` CI job builds this runtime, records the base
and final image IDs, and runs `make check-laboratory`. Native worker and
filesystem checks remain independent CI jobs.
