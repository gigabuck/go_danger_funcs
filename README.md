# go_danger_funcs
Simple python script to search for potentially dangerous Golang functions to aid in code review.

```
$ ./go_danger_funcs.py /mnt/c/Projects/foo
## Results:
/tmp/tmpbbatsm8u/file_input.txt
/tmp/tmpbbatsm8u/file_perm.txt
/tmp/tmpbbatsm8u/file_output.txt
/tmp/tmpbbatsm8u/path_manip.txt
/tmp/tmpbbatsm8u/code_exec.txt
/tmp/tmpbbatsm8u/http_svr_config.txt
/tmp/tmpbbatsm8u/http_tls_config.txt
/tmp/tmpbbatsm8u/http_redir.txt
/tmp/tmpbbatsm8u/http_cookie.txt
/tmp/tmpbbatsm8u/http_client.txt
```
