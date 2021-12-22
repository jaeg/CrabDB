# CrabDB

An attempt at a simple rest based json database.

### How to Run
#### Option 1: From source
- `make vendor`
- `make run`

#### Option 2: Build it
- `make vendor`
- `make build` - will build for current system architecture. 
- `make build-linux` - will build Linux distributable
- `make build-pi` - will build Raspberry Pi compatible distributable
- You will find the executable in the `./bin` folder.

#### Option 3: Docker
Linux images:
- `docker run -d jaeg/crabdb:latest`

Raspberry pi images:
- `docker run -d jaeg/crabdb:latest-pi`

### Configuration
Currently configuration is stored in the `./config` folder.  Inside there is:
- `encryptionkey` - stores the encryption key used to encrypt the databases.  Leave blank to not encrypt.
- `users.json` - on first boot CrabDB uses this file to setup the initial users.

###Rest Routes:

`/auth`:
- `Post`
    - Authenticate user using the basic auth header
    - returns jwt bearer token

`/db/<id>`:
- `Get`
    - returns current json
    - params: 
        - key - Option param for specific field or structure you want from database.  IE: config.base.entry. If not set returns the whole json from the db.
- `Put`
    - will update posted JSON in the database leaving what's not listed unchanged.
- `Delete`: 
    - will delete specific entry in JSON. 
    Example: config.base.entry would remove:
```{
    "config": {
        "base": {
            "entry":1
            }
        }
    }
```
