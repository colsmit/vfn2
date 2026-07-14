# Firmware QEMU Demo

This sample is a minimal firmware-rootfs layout for the automated
`discovery -> proof -> replay -> report` path. It is intentionally generic: runtime
code must infer the rootfs from filesystem layout and candidate facts, not from
this directory name.

Expected route/input facts:

- Binary: `rootfs/usr/bin/demo_cgi`
- Route: `POST /cgi-bin/demo`
- Input model: CGI form body, `payload=<bytes>`
- Bug class: non-crashing bounded-write overflow
- Proof target: QEMU user-mode memory-write observation

Build notes:

```bash
arm-linux-gnueabi-gcc -static -O0 -g -o rootfs/usr/bin/demo_cgi src/demo_cgi.c
chmod +x rootfs/usr/bin/demo_cgi
```

Acceptance command:

```bash
python -m binary_agent.cli.toolchain samples/firmware_qemu_demo/rootfs \
  --stages intake,discovery,refinement,proof,replay,report \
  --firmware-binary-regex 'demo_cgi$' \
  --replay-mode qemu_user \
  --output-root runs/acceptance_firmware_qemu \
  --overwrite
```
