"""No network clients or credentials here. OS isolation is a deployment concern."""
import logging
import sys
try:
    import resource
except ImportError:
    pass  # Windows: use the documented container/OS service boundary.
else:
    for _limit, _value in ((resource.RLIMIT_AS, (768*1024*1024,)*2), (resource.RLIMIT_CPU, (10, 10)),
                           (resource.RLIMIT_FSIZE, (0, 0)), (resource.RLIMIT_CORE, (0, 0)),
                           (resource.RLIMIT_NOFILE, (64, 64))):
        try:
            resource.setrlimit(_limit, _value)
        except (OSError, ValueError):
            pass  # Darwin rejects some hard limits; the container boundary still applies.
logging.disable(logging.CRITICAL)
from .documents import MAX_FILE, inspect_bytes
from .common import canonical

def main():
    result=inspect_bytes(sys.stdin.buffer.read(MAX_FILE+1),sys.argv[1])
    sys.stdout.buffer.write(canonical({**result.report(),'text':result.text}))

if __name__=='__main__':main()
