"""
Minifra Agent — Windows Service wrapper.
Install:   minifra-agent.exe install
Start:     minifra-agent.exe start
Stop:      minifra-agent.exe stop
Remove:    minifra-agent.exe remove
Run once:  minifra-agent.exe run   (foreground, useful for testing)
"""
import logging
import os
import sys
import time

# Ensure the agent module can be imported
sys.path.insert(0, os.path.dirname(__file__))

try:
    import win32service
    import win32serviceutil
    import win32event
    import servicemanager
    WIN32_AVAILABLE = True
except ImportError:
    WIN32_AVAILABLE = False


class MinifraAgentService(win32serviceutil.ServiceFramework if WIN32_AVAILABLE else object):
    _svc_name_ = "MinifraAgent"
    _svc_display_name_ = "Minifra Security Agent"
    _svc_description_ = "Minifra endpoint monitoring and security agent. Sends telemetry to the Minifra Hub."

    def __init__(self, args):
        if WIN32_AVAILABLE:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
        self._running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self._stop_event)
        self._running = False
        logging.getLogger("minifra-agent").info("Service stop requested")

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self._main_loop()

    def _main_loop(self):
        from agent import MinifraAgent
        agent = MinifraAgent()
        interval = agent.cfg.get("report_interval_s", 30)
        while self._running:
            agent.collect_and_report()
            # Use win32event for clean shutdown signal
            if WIN32_AVAILABLE:
                rc = win32event.WaitForSingleObject(self._stop_event, interval * 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    break
            else:
                time.sleep(interval)


def run_foreground():
    """Run the agent in the foreground (no Windows Service infrastructure needed)."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-8s  %(message)s",
        datefmt="%H:%M:%S",
    )
    from agent import MinifraAgent
    agent = MinifraAgent()
    try:
        agent.run()
    except KeyboardInterrupt:
        print("\nAgent stopped.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        # Launched by SCM (Service Control Manager)
        if WIN32_AVAILABLE:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(MinifraAgentService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            run_foreground()
    elif sys.argv[1] == "run":
        run_foreground()
    elif WIN32_AVAILABLE:
        win32serviceutil.HandleCommandLine(MinifraAgentService)
    else:
        print("pywin32 not available — use 'run' to start in foreground mode.")
        run_foreground()
