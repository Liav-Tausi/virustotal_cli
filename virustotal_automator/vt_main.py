import time
import vt_terminal

if __name__ == '__main__':
    start = time.perf_counter()
    print(vt_terminal.main())
    end = time.perf_counter()
    print(f"{round(end - start, 2)} second(s)")





