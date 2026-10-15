# Isolated service runtime

This image contains the Python runtime and pinned cryptography dependencies for
the [strict laboratory gate](../../docs/SERVICE_LABORATORY.md). Source code and
fixture evidence are mounted separately as a verified read-only snapshot.

Use an official CPython 3.14 slim image already reviewed and present locally.
Record its immutable image ID. For Linux amd64, download the wheels into a
disposable build directory with the repository environment:

```console
build_dir=$(mktemp -d)
cp laboratories/service-runtime/Dockerfile laboratories/service-runtime/requirements.txt "$build_dir/"
python -m pip download --index-url https://pypi.org/simple --only-binary=:all: \
  --require-hashes --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64 \
  --python-version 314 --implementation cp --abi cp314 \
  --dest "$build_dir/wheels" -r laboratories/service-runtime/requirements.txt
docker build --network none --pull=false --build-arg BASE_IMAGE=sha256:<reviewed-base-id> \
  --iidfile "$build_dir/image.id" "$build_dir"
make check-laboratory LABORATORY_ARGS="--runtime docker --image $(cat "$build_dir/image.id")"
```

On Linux arm64, replace both platform values with `manylinux_2_28_aarch64` and
`manylinux2014_aarch64`. The hashes cover only these two architectures and
CPython 3.14. Other runtimes need a separately reviewed lock. Network access is
used only to obtain prerequisites; the build and assessment run without it.
Remove the disposable build directory after retaining the image ID and result.

The Docker daemon must be able to bind-mount the temporary source snapshot.
With a macOS VM runtime, set `TMPDIR` to a disposable directory inside an
existing host share before invoking the gate. The launcher copies only its
allowlisted runtime and synthetic fixtures into that directory, mounts them
read-only, and removes the snapshot afterward. A directory outside the VM's
shares causes `container-create` to fail before any service activity.

The `isolated-service-laboratory` CI job builds this runtime, records the base
and final image IDs, and runs `make check-laboratory`. Native worker and
filesystem checks remain independent CI jobs.
