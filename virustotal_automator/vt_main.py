"""
vt_automator.
created by: liav tausi
date: 1/12/2023
"""

import vt_terminal
import time



if __name__ == '__main__':
    start = time.perf_counter()
    print(vt_terminal.main())
    end = time.perf_counter()
    print(round(end - start, 2), 'second(s)')









