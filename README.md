# IObox (win32)

IObox (win32) is a client-side utility for uploading and registering files to ERMrest+Hatrac services.

## System Requirements

IObox (win32) is a Python based utility. It is implemented on **Windows 7** as a service. The following are the prerequisites:

1. **Python** version 2.7+. Update the system PATH variable with the path to the directory containing the python exe, e.g., C:\Python27.
1. **pywin32**, Mark Hammond's add-on that includes the Win32 API, COM support, and Pythonwin extensions. It's available from the pywin32 project on SourceForge.
1. **setuptools** Python Package. For Windows 7, download ez_setup.py using your favorite web browser or other technique and **run** that file.
1. **py2exe** from SourceForge.


## Installation

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

## Configuration

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
   sha256, patterngroups, urlQuote`, etc. 
   at the start of the disposition sequence.
1. Each disposition block performs work and outputs some more
   metadata.  **ermrest** and **hatrac** handlers should output useful info
   like the resulting table row (including server-generated default
   column values) or object version.
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

Below is a sample of an configuration file. It:

1. Identifies a `slideid` from the file name.
1. Generates the `sha256` of the file.
1. Encodes URL values that will be used in the URL.
1. Defines Web Connections that will be used by **ermrest** and **hatrac**.
1. Creates an entry with the `Original Filename` and the `File Size`.
1. Uploads in **hatrac** the file.
1. Updates the entry with the `Filename` as its `sha256`.

```
{
    "log": "C:\\Users\\your_user_id\\Documents\\iobox\\log\\iobox.log",
    "loglevel": "debug",
    "timeout": 30,
    "mail_server": "smtp.mail_domain",
    "mail_sender": "IOBox Online Notification <no_reply@isi.edu>",
    "mail_receiver": "mail_id@mail_domain",
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
							"handler": "urlQuote",
							"prefix": "encode.",
							"resources": {
								"slideid": "%(slideid)s", 
								"sha256": "%(sha256)s",
								"schema": "Microscopy",
								"table": "Scan"
							}
						},
						{
							"handler": "templates",
							"templates": {
								"objname": "%(encode.schema)s/%(encode.slideid)s/%(encode.sha256)s.czi"
							}
						},
						{
							"handler": "webconn",
							"connections": {
								"foo": {
									"scheme": "https",
									"host": "foo.org",
									"use_goauth": true,
									"username": "my_user_name",
									"password": "my_password",
									"cookie": "ermrest=..."
								}
							}
						},
						{
							"handler": "ermrest",
							"method": "POST",
							"colmap": {
								"ID": "%(sha256)s",
								"Slide ID": "%(slideid)s",
								"Original Filename": "%(basename)s",
								"File Size": "%(nbytes)d"
							},
							"webconn": "foo",
							"url": "https://foo.org/ermrest/catalog/1/entity/%(encode.schema)s:%(encode.table)s"
						},
						{
							"handler": "hatrac",
    						"chunk_size": 100000000,
							"webconn": "foo",
							"url": "https://foo.org/hatrac/%(objname)s",
							"create_parents": true,
							"failure": "transfer"
						},
						{
							"handler": "ermrest",
							"method": "PUT",
							"group_key": {
								"ID": "%(sha256)s"
							},
							"target_columns": {
								"Filename": "%(sha256)s.czi"
							},
							"webconn": "foo",
							"url": "https://foo.org/ermrest/catalog/1/attributegroup/%(encode.schema)s:%(encode.table)s"
						}
					]
				}
			]
	    }
	]
}		

```

The sample is using the following:

1. Global parameters:

   - **log**: the service log file.
   - **loglevel**: the log level. Valid values are: `error, warning, info and debug`.
   - **timeout**: the waiting time in minutes before a retry process will occur.
   - **mail_server**: the mail server used to send status notifications.
   - **mail_sender**: the sender of the mail notifications.
   - **mail_receiver**: the receiver of the mail notifications.

1. Directory parameters:

   - **inbox**: the directory the service is watching for new files.
   - **success**: the directory the service is moving the files in case of success.
   - **failure**: the directory the service is moving the files in case of failure.
   - **retry**: the directory the service is moving the files in case of database failure.
   - **transfer**: the directory the service is moving the files in case of **hatrac** failure.

1. Rule:

   - **pattern**: the pattern used in matching the file names. 
     For example, a valid name will be `http---cirm.7.purl.org-?id=20131110-wnt1creZEGG-RES-0-06-000.czi`.
   - **"handler": "patterngroups"**: identifies the `slideid` from the file name 
     (in our example `20131110-wnt1creZEGG-RES-0-06-000`). The Python dictionary is
     updated with the key `slideid`.
   - **"handler": "sha256"**: generates the `sha256` of the file. The Python dictionary is
     updated with the key `sha256`.
   - **"handler": "urlQuote"**: encodes URL the values specified by the `resources`.
     The Python dictionary is updated with the keys `encode.slideid, 
     encode.sha256, encode.schema and encode.table`.
   - **"handler": "templates"**: defines a template that will be used by **hatrac**.
     The Python dictionary is updated with the key `objname`.
   - **"handler": "webconn"**: defines the Web connection to be used by **ermrest** and
     **hatrac**. The Python dictionary is updated with the key `foo`.
   - **"handler": "ermrest"** with `"method": "POST"`. The `colmap`
     specifies the columns that will be updated.
   - **"handler": "hatrac"**: Uploads the file in chunks and create the
     parent namespaces if absent. In case of failure, move the file to
     the `transfer` directory.
   - **"handler": "ermrest"** with `"method": "PUT"`. The `group_key`
     specifies the columns to identify the entity that will be updated.
     The `target_columns` specifies the columns that will be updated.

## Troubleshooting

Normally, the application will end gracefully once the service is stopped. 
In the case the service can not be stopped, create an empty file named 
"stop_service.txt" and place it in the **inbox** directory.
