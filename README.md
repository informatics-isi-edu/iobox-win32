# IObox (win32)

IObox (win32) is a client-side utility for uploading and registering files to ERMrest+Hatrac services.

## System Requirements

IObox (win32) is a Python based utility. It is implemented on **Windows 7** as a service. The following are the prerequisites:

1. **Python** version 2.7+.
1. **pywin32**, Mark Hammond's add-on that includes the Win32 API, COM support, and Pythonwin extensions. It's available from the pywin32 project on SourceForge.
1. **setuptools** Python Package. For Windows 7, download ez_setup.py using your favorite web browser or other technique and **run** that file.
1. **py2exe** from SourceForge.


## Installation

1. Check out the code from GitHub:

    git clone https://github.com/informatics-isi-edu/iobox-win32.git 

1. Go into the **src\service** directory.

1. Run:

    python setup.py py2exe

  Two directories will be created: **build** and **dist**. Remove the **build** directory.

1. Open a **Command Prompt** window in **Run as Administrator** mode.
   
1. Go into the **src\service\dist** directory.  
   
1. Install the service by running:
   
    CirmObserverService.exe -install

1. In the **Services** Windows console, you will find the service named **IOBox**.

1. Right click the service and select **Properties**. Select the **Log On** tab. Check the **This account** box. Enter the user and the password for running this service. The setting is necessary because the service needs permission to write in the application log file. Select the **General** tab. Select **Automatic** for the **Startup type**. The service will start automatically after reboot.
     
1. To uninstall the service, while the service is stopped, from the **src\service\dist** directory, run:

    CirmObserverService.exe -remove

## Configuration

IObox (win32) will look for the configuration file at:

`%HOMEPATH%\Documents\scans\config\outbox.conf`

The following is a sample of the configuration file:

```
{
    "url": "https://cirm-dev.misd.isi.edu/ermrest/catalog/1",
    "goauthtoken": true,
    "inbox": "C:\\Users\\your_user_id\\Documents\\scans\\inbox",
    "outbox": "C:\\Users\\your_user_id\\Documents\\scans\\outbox",
    "rejected": "C:\\Users\\your_user_id\\Documents\\scans\\rejected",
    "retry": "C:\\Users\\your_user_id\\Documents\\scans\\retry",
    "transfer": "C:\\Users\\your_user_id\\Documents\\scans\\transfer",
    "log": "C:\\Users\\your_user_id\\Documents\\scans\\log\\cirm_iobox.log",
    "loglevel": "debug",
    "username": "your_user_id",
    "password": "your_password",
    "pattern": ".*id=(?P<slideid>.*[-][0-9]*)[.]czi",
    "timeout": 30,
    "mail_server": "smtp.isi.edu",
    "mail_sender": "CIRM Online Notification <no_reply@isi.edu>",
    "mail_receiver": "serban@isi.edu"
}
```

The required parameters are:

- url: The ERMREST URL
- inbox: the directory the service is watching for new files
- outbox: the directory the service is moving the files in case of success
- rejected: the directory the service is moving the files in case of failure
- retry: the directory the service is moving the files in case of database failure
- transfer: the directory the service is moving the files in case of Globus transfer failure
- username: the GO username
- password: the GO password
- pattern: the pattern used in matching the file names. 
For example, a valid name will be `"http---cirm.7.purl.org-?id=20131110-wnt1creZEGG-RES-0-06-000.czi"`.
	
The optional parameters are:	
	
- goauthtoken: if "true", then the service is using GO authentication
- log: the service log file
- loglevel: the log level. Valid values are: "error", "warning", "info" and "debug".
- timeout: the waiting time in minutes before a retry process will occur.
- mail_server: the mail server used to send status notifications.
- mail_sender: the sender of the mail notifications.
- mail_receiver: the receiver of the mail notifications.
	
## Troubleshooting

Normally, the application will end gracefully once the service is stopped. In the case the service can not be stopped, create an empty file named "stop_service.txt" and
place it in the "inbox" directory.