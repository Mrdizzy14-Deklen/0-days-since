# Nemotron on a Brev GPU (optional, for demos)

Runs `nvidia/nemotron-3.5-super-vl-120b-a12b` on a dedicated GPU instead of NVIDIA's shared
hosted API, so scan times stop depending on someone else's queue. Pay only while it runs:
start it before a demo, stop it after.

```
Brev GPU                                   Vultr server
NIM container 127.0.0.1:8000  --ssh -R-->  127.0.0.1:8100  <--  backend (LLM_BASE_URL)
(not exposed to the internet)              (tunnel user can only forward this one port)
```

The backend keeps NVIDIA's hosted API as its fallback, so if the Brev instance stops or the
tunnel drops, scans still work, just at hosted-API speed.

## 1. One-time setup

```bash
brew install brevdev/homebrew-brev/brev
brev login
```

In the Brev console create an instance:

- **Mode:** VM mode (not container mode)
- **GPU:** **1x H200** (cheapest supported option) or **2x H100 80GB**. Other GPUs are not
  supported by this model's NVFP4 profiles (see NVIDIA's NIM page for the full list)
- **Disk:** 200 GB or more (the model is ~80 GB, plus the container image)
- **Name:** e.g. `zeroday-nim`

The NGC key used to pull the container defaults to your `LLM_API_KEY` (an `nvapi-` key from
build.nvidia.com). If that is refused, create a key at ngc.nvidia.com > Setup > API Key and add
`NGC_API_KEY=...` to `backend/.env`.

## 2. Before the demo (first run: allow ~30-60 min for the model download)

```bash
deploy/brev/up.sh zeroday-nim 64.177.52.231
```

It authorizes the tunnel on Vultr, starts the NIM with the right profile for the GPU, waits
until the model is loaded, then switches the backend over (`backend/.env.local` on the
server, which is never synced or committed). Later starts reuse the cached model.

## 3. After the demo

```bash
deploy/brev/down.sh 64.177.52.231 zeroday-nim
```

Switches the backend back to the hosted API and stops the instance so billing stops.

## Checking it

```bash
ssh zeroday-nim 'docker logs --tail 20 nim; systemctl status nim-tunnel --no-pager | head -5'
ssh root@64.177.52.231 'curl -s 127.0.0.1:8100/v1/models; journalctl -u zeroday-backend -n 20 | grep timings'
```

Each push page's **Agent** tab shows how long every step and phase took.
