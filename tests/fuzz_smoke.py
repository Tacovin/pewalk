"""
Dumb mutation fuzzing: flip random bytes / truncate real PE files and make
sure pewalk never crashes. Exit code 0 or 1 is fine, anything else
(access violation, abort) is a bug.

    python tests/fuzz_smoke.py build/pewalk.exe C:/Windows/System32/notepad.exe 2000
"""
import os
import random
import subprocess
import sys
import tempfile


def mutate(data, rnd):
    data = bytearray(data)
    how = rnd.randrange(4)
    if how == 0:
        # random bytes anywhere
        for _ in range(rnd.randrange(1, 50)):
            data[rnd.randrange(len(data))] = rnd.randrange(256)
    elif how == 1:
        # hit the headers, that's where the interesting fields are
        for _ in range(rnd.randrange(1, 20)):
            data[rnd.randrange(min(len(data), 0x400))] = rnd.randrange(256)
    elif how == 2:
        data = data[:rnd.randrange(64, len(data))]
    else:
        # write a big dword somewhere in the headers
        off = rnd.randrange(0, min(len(data), 0x400) - 4)
        data[off:off + 4] = rnd.choice([0xFFFFFFFF, 0x7FFFFFFF, 0x80000000, len(data)]).to_bytes(4, "little")
    return bytes(data)


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    tool = os.path.abspath(sys.argv[1])
    seed = open(sys.argv[2], "rb").read()
    rounds = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
    rnd = random.Random(1337)

    crashes = 0
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "case.bin")
        for i in range(rounds):
            case = mutate(seed, rnd)
            with open(path, "wb") as f:
                f.write(case)
            for args in ([tool, path], [tool, "-i", "-e", "-j", path]):
                r = subprocess.run(args, capture_output=True, timeout=10)
                if r.returncode not in (0, 1):
                    crashes += 1
                    keep = f"crash_{i}.bin"
                    with open(keep, "wb") as f:
                        f.write(case)
                    print(f"round {i}: exit code {r.returncode:#x}, saved {keep}")
                    break

    print(f"{rounds} rounds, {crashes} crashes")
    return 1 if crashes else 0


if __name__ == "__main__":
    sys.exit(main())
