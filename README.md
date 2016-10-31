# IObox

IObox is a client-side utility for uploading and registering files to ERMrest+Hatrac services. 
It is implemented on WIN32 as well as on Linux.

## IObox WIN32 System Requirements

IObox WIN32 is a Python based utility. It is implemented on **Windows 7** as a service. The following are the prerequisites:

1. **Python** version 2.7+. Update the system PATH variable with the path to the directory containing the python exe, e.g., C:\Python27.
1. **pywin32**, Mark Hammond's add-on that includes the Win32 API, COM support, and Pythonwin extensions. It's available from the pywin32 project on SourceForge. (https://sourceforge.net/projects/pywin32/)
1. **setuptools** Python Package. For Windows 7, download ez_setup.py using your favorite web browser or other technique and **run** that file.
1. **py2exe** from SourceForge.


## IObox WIN32 Installation

1. Check out the code from GitHub:

    ```git clone https://github.com/informatics-isi-edu/iobox-win32.git``` 

1. Go into the **src\service** directory.

1. Run:

    ```python setup.py py2exe```

  Two directories will be created: **build** and **dist**. Remove the **build** directory.

1. Open a **Command Prompt** window in **Run as Administrator** mode.
   
1. Go into the **src\service\dist** directory.  
   
1. Install the service by running:
   
    ```IOBoxObserverService.exe -install```

1. In the **Services** Windows console, you will find the service named **IOBox**.

1. Right click the service and select **Properties**. Select the **Log On** tab. Check the **This account** box. Enter the user and the password for running this service. The setting is necessary because the service needs permission to write in the application log file. Select the **General** tab. Select **Automatic** for the **Startup type**. The service will start automatically after reboot.
     
1. To uninstall the service, while the service is stopped, from the **src\service\dist** directory, run:

    ```IOBoxObserverService.exe -remove```

## IObox Linux System Requirements

IObox Linux is a Python based utility. It is implemented on **CentOS 7** or **Fedora** as an agent. The following are the prerequisites:

1. **Python** version 2.7+.
1. **scandir**. Install it with:
  - `yum install python-scandir` on CentOS + EPEL
  - `yum install python2-scandir` on Fedora
  - `pip install scandir` on other Python environments

## IObox Linux Installation

1. Check out the code from GitHub:

    ```git clone https://github.com/informatics-isi-edu/iobox-win32.git``` 

1. Go into the **iobox-win32** directory.

1. Run:

    ```python setup.py install```

  The  **build** directory will be created. Remove it.

1. To start the agent run:

    ```iobox-agent [-c <configuration_file>]```
    
    If the `-c` option is missing, the `~/.iobox.conf` file will be considered.
      
1. To stop the agent, identify first the process id by running:

    ``` ps -ef | grep iobox-agent```
    
    and then kill the process by running:
    
    ```kill <process_id>```
   
## IObox Configuration

IObox strategy is based on disposition rules. There is a config stanza for each monitored directory, doing the following:

1. Process ordered list of disposition rules, applying regular-expression match 
   on a pattern in each rule against the newly discovered filename.
   The **first** matching rule is applied and break out of the processing loop,
   i.e. only one rule block is executed per file.
1. In rule block, process an ordered list of work units, each of which
   reference a built-in handler by keyword.
   - The build-in handler is passed the filename, an accumulation of
     metadata, and the work unit document (JSON) where it might find
     handler-specific configuration data.
   - The handler may interact with outside world and can raise
     exceptions for fatal conditions.  An exception aborts the work
     sequence, skipping subsequent work units for the same file.
   - The handler returns new metadata that is incorporated into the
     accumulation passed to subsequent handlers.  The accumulation
     will optional prefix metadata field names based on the presence
     of a `prefix` key in the rule block.
1. We provide some basic metadata like `basename, nbytes, 
   sha256, md5sum, mtime, patterngroups, urlQuote`, etc. 
   at the start of the disposition sequence.
1. The **mtime** handler  generates the UTC last modification timestamp 
   of the file in the format `%Y-%m-%d %H:%M:%S.%f`. The format 
   directives are the ones used by Python.
1. The **datetime** handler converts a timestamp defined in the `input` 
   section from one format to another one defined in the `output` 
   section. The input timestamp string is defined in the `date_string` 
   parameter and its format in the `format` parameter. The `output` 
   section contains the format to convert to. Example:

   ```
      {
         "handler": "datetime",
         "input": {
                  "date_string": "2016-05-06 20:39:08.982442",
                  "format": "%Y-%m-%d %H:%M:%S.%f"
               },
         "output": {
                  "date": "%Y-%m-%d"
                }
      }

   ```
1. Each disposition block performs work and outputs some more
   metadata.  **ermrest** and **hatrac** handlers should output useful info
   like the resulting table row (including server-generated default
   column values) or object version. For the **ermrest** handler, 
   the **colmap** specifies the body request with the columns 
   mapping to be created or updated. Example:

   ```
      {
         "handler": "ermrest",
         "method": "POST",
         "colmap": {
                  "column1": 1,
                  "column2": "foo"
               },
         "url": "https://foo.org/ermrest/catalog/1/entity/table1"
      }

   ```
   The **POST** request, will create a row and will return a **409 Conflict** 
   error response if it already exists, while the **PUT** _entity_ request 
   will create a row if no match is found or update it if it already exists. 
   For the **PUT** _attributegroup_ request, you specify in the URL the **group_key** to
   identify the matching columns that will cause an row to be updated and 
   the **target_columns** to specify the columns to be updated. The **colmap** specifies 
   the body of the request containing the values for the **group_key** and 
   **target_columns** columns. Example:

   ```
      {
         "handler": "ermrest",
         "method": "PUT",
         "colmap": {
                  "column1": 1,
                  "column2": "foo"
               },
         "url": "https://foo.org/ermrest/catalog/1/attributegroup/table1/column1;column2"
       }

   ```
1. In the **hatrac** handlers, if the md5sum of the file to be uploaded 
   matches the one existing in **hatrac**, then the upload process is skipped.
1. Output metadata are optional qualified with a **prefix** of that block.
   It is the user responsibility to define a `prefix` wherever 
   collisions might occur. A block can reference metadata from
   any previous block in its document. This is important so a single
   handler can be invoked more than once and its outputs
   distinguished by different prefixes, e.g. several **ermrest**
   submissions or several **hatrac** uploads.
1. We use Python dictionary interpolation templates in almost any
   right-hand-side string value in the disposition blocks, so that
   metadata can be incorporated into config values passed to the
   handlers. The basic handler names themselves are not
   interpolated.
1. We wrap each of our custom processing tasks as reusable handlers
   and register them in the finite set of named handlers in a
   particular release of the iobox tool. This will eventually
   include extra stuff like **czifile** and **tifffile** based metadata
   extractors.
1. The **templates** handler allows us to refactor
   some metadata into an intermediate result that is then shared
   among several subsequent handlers. This avoids repeating
   ourselves for certain key values that integrate our actions,
   e.g. using an object name to **hatrac** and to **ermrest**.
1. We might have additional parameters to each work units to describe
   failure/retry policies or overrides.

IObox (win32) will look for the configuration file at `%HOMEPATH%\Documents\iobox\config\outbox.conf`. 
If the configuration file does not exist, or is invalid, then the Windows service 
will not start, and the error will be logged into the `%HOMEPATH%\Documents\iobox_service.log` file. 
Example of such messages:
```
2016-05-16 11:30:04,717: ERROR <serviceconfig>: Configuration file: "C:\Users\your_user_id\Documents\iobox\config\outbox.conf" does not exist.
2016-05-16 11:31:30,269: ERROR <serviceconfig>: Malformed configuration file: Expecting property name: line 56 column 8 (char 1548)
```
Below is a sample of an configuration file. It:

1. Identifies a `slideid` from the file name.
1. Generates the `sha256` of the file.
1. Encodes URL values that will be used in the URL.
1. Defines Web Connections that will be used by **ermrest** and **hatrac**.
1. Creates or updates an entity with the `ID`, `Slide ID`, `Original Filename`, `MD5`, `File Size` and the `Modified Date`.
1. Uploads in **hatrac** the file.
1. Updates the entry with the `Filename` as its `sha256`.
1. Provides daily reports.

```
{
    "log": "C:\\Users\\your_user_id\\Documents\\iobox\\log\\iobox.log",
    "loglevel": "debug",
    "timeout": 30,
    "scan_interval": 5,
    "mail": {
    	"server": "smtp.mail_domain",
    	"sender": "IOBox Online Notification <no_reply@isi.edu>",
    	"receiver": "mail_id@mail_domain",
    	"actions": ["ERROR"]
    },
	"connections": {
		"foo": {
			"scheme": "https",
			"host": "foo.org",
			"credentials": "C:\\Users\\your_user_id\\Documents\\iobox\\config\\credentials.json"
		}
	},
    "report": {
    	"output": "C:\\Users\\your_user_id\\Documents\\iobox\\reports",
    	"prefix": "foo",
		"webconn": "foo",
    	"actions": ["success", "failure", "duplicate", "retry"],
    	"catalog": 1,
    	"schema": "Report",
    	"table": "Report",
    	"colmap": {
    		"timestamp": "Created",
    		"filename": "File Name",
    		"status": "Action",
    		"reason": "Reason",
    		"reported": "Notified"
		}
    },
	"monitored_dirs": [
		{
		    "inbox": "C:\\Users\\your_user_id\\Documents\\iobox\\input",
		    "success": "C:\\Users\\your_user_id\\Documents\\iobox\\success",
		    "failure": "C:\\Users\\your_user_id\\Documents\\iobox\\failure",
		    "retry": "C:\\Users\\your_user_id\\Documents\\iobox\\retry",
		    "transfer": "C:\\Users\\your_user_id\\Documents\\iobox\\transfer",
		    "rules": [
		    	{
					"pattern": ".*id=(?P<slideid>.*[-][0-9]*)[.]czi",
					"disposition" : [
						{
							"handler": "patterngroups"
						},
						{
							"handler": "sha256"
						},
						{
							"handler": "md5sum"
						},
						{
							"handler": "mtime"
						},
						{
							"handler": "datetime",
							"input": {
										"date_string": "%(mtime)s",
										"format": "%Y-%m-%d %H:%M:%S.%f"
									 },
							"output": {
										"last_modified_date": "%Y-%m-%d"
									  }
						},
						{
							"handler": "urlQuote",
							"prefix": "encode.",
							"output": {
								"slideid": "%(slideid)s", 
								"sha256": "%(sha256)s",
								"schema": "Microscopy",
								"table": "Scan"
							}
						},
						{
							"handler": "templates",
							"output": {
								"objname": "%(encode.schema)s/%(encode.slideid)s/%(encode.sha256)s.czi"
							}
						},
						{
							"handler": "ermrest",
							"method": "POST",
							"warn_on_duplicates": true,
							"colmap": {
								"ID": "%(sha256)s",
								"Slide ID": "%(slideid)s",
								"Original Filename": "%(basename)s",
								"MD5": "%(md5sum)s",
								"File Size": "%(nbytes)d",
								"Modified Date": "%(last_modified_date)s",
								"HTTP URL": null,
								"Thumbnail": null
							},
							"webconn": "foo",
							"url": "https://foo.org/ermrest/catalog/1/entity/%(encode.schema)s:%(encode.table)s"
						},
						{
							"handler": "hatrac",
							"warn_on_duplicates": true,
    						"chunk_size": 10000000,
							"webconn": "foo",
							"url": "https://foo.org/hatrac/%(objname)s",
							"create_parents": true,
							"failure": "transfer"
						},
						{
							"handler": "ermrest",
							"method": "GET",
							"webconn": "foo",
							"continueAfter": ["ZERO_RESULT"],
							"url": "https://foo.org/ermrest/catalog/1/attribute/%(encode.schema)s:Experiment/Disambiguator=H/Probe"
						},
						{
							"handler": "ermrest",
							"method": "PUT",
							"colmap": {
								"ID": "%(sha256)s",
								"Filename": "%(sha256)s.czi",
								"Probe": "%(Probe)s"
							},
							"webconn": "foo",
							"url": "https://foo.org/ermrest/catalog/1/attributegroup/%(encode.schema)s:%(encode.table)s/ID;Filename,Probe"
						}
					]
				}
			]
	    }
	]
}		

```

Example of a credentials file:

```
{
	"username": "my_user_name",
	"password": "my_password",
	"cookie": "ermrest=..."
}

```

The sample is using the following:

1. Global parameters:

   - **log**: the service log file.
   - **loglevel**: the log level. Valid values are: `error, warning, info and debug`.
   - **timeout**: the waiting time in minutes before a retry process will occur.
   - **scan_interval**: the waiting time in minutes before a rescanning of the input directory occurs in case no file change event was triggerred.
   - **mail**: the mail configuration for sending status notifications. It defines the following:
       - **server**: the mail server used for sending notifications.
       - **sender**: the sender of the mails.
       - **receiver**: the receiver of the mails.
       - **actions**: an array having any combination of the "INFO", "WARNING" and "ERROR" elements. The default is ["INFO", "WARNING", "ERROR"]. The sample will email only ERROR messages.
   - **connections**: defines the Web connections to be used by the **ermrest** and **hatrac** handlers. 
     The connection is identified by a name that might be referred in those handlers. The parameter **credentials** points to a JSON file that contains 
     the  credential information. 
   - **report**: if present, it should specify that daily activity reports should be submitted by email. Its structure consists of:
     - **output**: the directory where the daily reports are generated
     - **prefix**: the prefix of the report file. The default is `Report`. The report file names follow the pattern `<prefix>.YYYY-MM-DD.csv`, where `YYYY-MM-DD` is its creation date.
     - **connection**: defines the Web connection to be used for creating reports. The parameter **credentials** points to a JSON file that contains the  credential information.
     - **actions**: an array with the actions to be reported. The default is `["success", "failure", "duplicate", "retry"]`.
     - **catalog**: the catalog where the report data is stored. The default is `1`.
     - **schema**: the schema where the report data is stored.
     - **table**: the table where the report data is stored. The table should have the columns specified in `colmap`. In addition, it can have columns with default values (for example a column of type `serial`).
     - **colmap**: the map between the report columns and their real names. The report table should have the following columns:
         - **timestamp**: a column of `timestamptz` type to store the activity creation time
         - **filename**: a column of `text` type to store the involved file name
         - **status**: a column of `text` type to store the activity result. It has values like `success`, `failure`, `duplicate` and `retry`.
         - **reason**: a column of `text` type to store the reason of a failure.
         - **reported**: a column of `boolean` type to mark if the data was reported or not.

1. Directory parameters:

   - **inbox**: the directory the service is watching for new files.
   - **success**: the directory the service is moving the files in case of success.
   - **failure**: the directory the service is moving the files in case of failure.
   - **retry**: the directory the service is moving the files in case of database failure.
   - **transfer**: the directory the service is moving the files in case of **hatrac** failure.

1. Rule:

   - **pattern**: the pattern used in matching the file names. 
     For example, a valid name will be `http---cirm.7.purl.org-?id=20131110-wnt1creZEGG-RES-0-06-000.czi`.
   - **relpath_matching**: if present and equal to `true`, the pattern will be applied to the relative path of the file. 
     By default, the pattern is applied to the basename of the file.
   - **dir_cleanup_patterns**: if present, it contains an array of patterns. Empty subdirectories of the `inbox` will 
     be deleted only if their relative path matches any of the patterns of `dir_cleanup_patterns`. By default, 
     all the empty subdirectories of the `inbox` will be deleted.
   - **"handler": "patterngroups"**: identifies the `slideid` from the file name 
     (in our example `20131110-wnt1creZEGG-RES-0-06-000`). The Python dictionary is
     updated with the key `slideid`.
   - **"handler": "sha256"**: generates the `sha256` of the file. The Python dictionary is
     updated with the key `sha256`.
   - **"handler": "md5sum"**: generates the `base64` of the `md5` digest string of the file. The Python 
     dictionary is updated with the key `md5sum`.
   - **"handler": "mtime"**: generates the last modification timestamp of the file in the 
     `%Y-%m-%d %H:%M:%S.%f` format. The Python dictionary is updated with the key `mtime`.
   - **"handler": "datetime"**: generates the last modification date of the file by 
     converting the last modification timestamp of the file to the `%Y-%m-%d` format.
     The result updates the Python dictionary with the key `last_modified_date`.
   - **"handler": "urlQuote"**: encodes URL the values specified in the `input`.
     The Python dictionary is updated with the keys `encode.slideid, 
     encode.sha256, encode.schema and encode.table`.
   - **"handler": "templates"**: defines a template that will be used by **hatrac**.
     The Python dictionary is updated with the key `objname`.
   - **"handler": "ermrest"** with `"method": "POST"`. The `colmap`
     specifies the columns that will be updated. The **warn_on_duplicates** parameter 
     specifies that duplicates detected at `ermrest` will be notified through the email.
   - **"handler": "hatrac"**: Uploads the file in chunks and create the
     parent namespaces if absent. In case of failure, move the file to
     the `transfer` directory. The **warn_on_duplicates** parameter specifies 
     that duplicates detected at `hatrac` will be notified through the email.
   - **"handler": "ermrest"** with `"method": "GET"`. The request must return 
     exactly one row; an error is reported otherwise. The Python dictionary is 
     updated with the columns and values returned by the row. The `continueAfter` 
     option contains an array with the following valid values:
      - `"ZERO_RESULT"` specifies to continue in case the `GET`request returns zero rows. 
      - `"*"` specifies to continue in case of any `ermrest` error
      - a numeric `value`: specifies to continue in case the `ermrest` error matches the numeric `value`.
   - **"handler": "ermrest"** with `"method": "PUT"`. The `group_key`
     specifies the columns to identify the entity that will be updated.
     The `target_columns` specifies the columns that will be updated. The 
     `Probe` attribute returned from the previous **ermrest** handler with 
     the `GET` method is used here to populate the `Probe` column of the 
     `Scan` table.

## Troubleshooting

Normally, the application will end gracefully once the service is stopped. 
In the case the service can not be stopped, create an empty file named 
"stop_service.txt" and place it in the **inbox** directory.
