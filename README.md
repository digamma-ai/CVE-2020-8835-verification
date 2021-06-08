Formal vefication of [CVE-2021-31440](https://www.zerodayinitiative.com/blog/2021/5/26/cve-2021-31440-an-incorrect-bounds-calculation-in-the-linux-kernel-ebpf-verifier)

## Set up environment

- Install Linux headers: `sudo apt install linux-headers-$(uname -r)`
- Install coq-config: `pip install coq-config`
- Install OPAM: `apt-get install opam`
- Initialize switch: `coq-config`
- Switch to the new OPAM switch: `opam switch ebpf_bug` (you may need to
  re-open your shell after that)

## Compile Project

- `make`

## Contact and further info

-  [Digamma.ai](http://digamma.ai)
