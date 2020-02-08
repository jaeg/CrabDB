CrabDB

An attempt at a distributed json database.

Rest Routes:

/db/<id>:
- Get: returns current json
- Post: will update posted JSON in the database leaving what's not listed unchanged.
- Delete: will delete specific entry in JSON.  Example: config.base.entry would remove {"config":{"base":{"entry":1}}}

