https://stackoverflow.com/a/65432506/7125878

```
openssl req -new -subj "/C=US/ST=Utah/CN=localhost" -newkey rsa:2048 -nodes -keyout localhost.key -out localhost.csr
```

```
openssl x509 -req -days 365 -in localhost.csr -signkey localhost.key -out localhost.crt
```
