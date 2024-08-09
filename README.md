# go-authenticated_resource_locator
Go implementation of the ARL library.

Describes a way to specify access to a remote resource, supporting many methods, and including auth data, and all that within a single string.

Currently supported (method: auths):

* **http**: basic, bearer, token, otx, None
* **https**: basic, bearer, token, otx, None
* **gcs**: gaia
* **github**: token, None

On GitHub, all files within the repo (or subdirectory) of the repo will be iterated on via the REST API.

## Format

```
[methodName,methodDest,authType,authData]
```

or if the `authType` and `authData` are omitted, no authentication is used (only available in some methods).

```
[methodName,methodDest]
```

Examples:

HTTP GET with Basic Auth: `[https,my.corpwebsite.com/resourdata,basic,myusername:mypassword]`

Access using Authentication bearer: `[https,my.corpwebsite.com/resourdata,bearer,bfuihferhf8erh7ubhfey7g3y4bfurbfhrb]`

Access using Authentication token: `[https,my.corpwebsite.com/resourdata,token,bfuihferhf8erh7ubhfey7g3y4bfurbfhrb]`

Google Cloud Storage: `[gcs,my-bucket-name/some-blob-prefix,gaia,base64(GCP_SERVICE_KEY)]`

GitHub repo: `[github,my-org/my-repo-name,token,bfuihferhf8erh7ubhfey7g3y4bfurbfhrb]`

GitHub repo to specific file: `[github,my-org/my-repo-name/path/to/file,token,bfuihferhf8erh7ubhfey7g3y4bfurbfhrb]`

You can also omit the auth components to just describe a method: `[https,my.corpwebsite.com/resourdata]`

## Return Value
The return value is a generator of tuples (fileName, fileData).

If pointing to a single file via HTTP for example, only one tuple will be
generated. However if pointing to a git repo (without specifying the path to the specific requested file),
a zip or tar file, all the files will be generated where fileName will be a complete path from the source.
