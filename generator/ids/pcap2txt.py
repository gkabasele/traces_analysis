import os
import argparse
from subprocess import Popen, PIPE

parser = argparse.ArgumentParser()
parser.add_argument("--indir", type=str, dest="indir", action="store")
parser.add_argument("--outdir", type=str, dest="outdir", action="store")

args = parser.parse_args()
indir = args.indir
outdir = args.outdir

if not os.path.exists(outdir):
    os.mkdir(outdir)

for f in os.listdir(indir):
    filename = os.path.join(indir, f)
    out = "{}.txt".format(f[:-5])
    outname = os.path.join(outdir, out)

    cmd = ["tcpdump", "-nNqttr", filename]

    out, err = Popen(cmd, stdout=PIPE).communicate()
    if not err:
        with open(outname, "a") as f:
            f.write(out)
