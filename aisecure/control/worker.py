"""No network clients or credentials here. OS isolation is a deployment concern."""
import logging
import sys
try:
    import resource
    resource.setrlimit(resource.RLIMIT_AS, (768*1024*1024, 768*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
except ImportError:
    pass  # Windows: use the documented container/OS service boundary.
logging.disable(logging.CRITICAL)
from .documents import MAX_FILE, inspect_bytes
from .common import canonical

def main():
    result=inspect_bytes(sys.stdin.buffer.read(MAX_FILE+1),sys.argv[1])
    sys.stdout.buffer.write(canonical({**result.report(),'text':result.text}))

if __name__=='__main__':main()
