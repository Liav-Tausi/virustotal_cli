import os
import pickle
import vt_terminal


if __name__ == '__main__':
    try:
        if not os.path.exists('vt_auto.pickle'):
            vt_automator = vt_terminal.main()
        else:
            with open('vt_auto.pickle', 'rb') as fh:
                vt_automator = pickle.load(fh)

        print(vt_terminal.main())

    finally:
        with open('vt_auto.pickle', 'wb') as fh:
            pickle.dump(vt_automator, fh)
