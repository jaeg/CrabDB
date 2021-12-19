# CrabDB

An attempt at a simple rest based json database for use within a kubernetes cluster.

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
