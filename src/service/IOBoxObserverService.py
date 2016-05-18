# 
# Copyright 2016 University of Southern California
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import win32serviceutil
import win32service
import win32event
import servicemanager
import serviceconfig


class IOBoxObserverService(win32serviceutil.ServiceFramework):
    _svc_name_ = 'IOBox'
    _svc_display_name_ = 'IOBox'
    _svc_description_ = 'IOBox service for registering files'

    
    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.isAlive = True


    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        servicemanager.LogInfoMsg("stopping...")
        if self.observerManager:
            self.observerManager.stop()
        self.isAlive = False

        
    def SvcDoRun(self):
        servicemanager.LogInfoMsg("starting...")
        self.observerManager = serviceconfig.load()
        if self.observerManager:
            self.observerManager.start()
            win32event.SetEvent(self.hWaitStop)
        else:
            errorMessage = serviceconfig.getLogErrorMsg()
            if errorMessage != None:
                servicemanager.LogErrorMsg(errorMessage)

