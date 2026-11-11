import os, runpy, sys
from pyinstrument import Profiler

here = os.path.dirname(os.path.abspath(__file__))
sys.argv = ["bench_url_scanner.py", sys.argv[1], "1"]
p = Profiler(interval=0.001)
p.start()
runpy.run_path(os.path.join(here, "bench_url_scanner.py"), run_name="__main__")
p.stop()
print(p.output_text(unicode=False, color=False))