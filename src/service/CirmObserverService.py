import win32serviceutil
import win32service
import win32event
import servicemanager
import serviceconfig


class CirmObserverService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'CIRMIOBox'
    _svc_display_name_ = 'CIRM IOBox'
    _svc_description_ = 'CIRM service for registering files'

    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isAlive = True


    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        servicemanager.LogInfoMsg("stopping...")
        if self.observer:
            self.observer.stop()
        self.isAlive = False

        
    def SvcDoRun(self):
        servicemanager.LogInfoMsg("starting...")
        self.observer = serviceconfig.load()
        if self.observer:
            self.observer.start()
            win32event.SetEvent(self.hWaitStop)

