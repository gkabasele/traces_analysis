import time
from threading import Timer

class RepeatedTimer(object):

    """Repeat `function` every `interval` seconds."""

    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
             self._timer = Timer(self.interval, self._run)
             self._timer.start()
             self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False


class Browser(object):

    def __init__(self, a):
        self.a = 12

    def display(self):
        print "The value of a: %s" % self.a

def main():

    browser = Browser(10)
    rt  = RepeatedTimer(1, browser.display)

    try:
        time.sleep(10)
    finally:
        rt.stop()


if __name__ == "__main__":
    main()
