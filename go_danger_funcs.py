#!/usr/bin/python3

import os
import sys
import glob
import tempfile
import sqlite3
import base64

if len (sys.argv) != 3:
    print("Usage: go_dangerous_funcs.py [source_directory] [vendor_include]")
    sys.exit(1)

search_path = sys.argv[1]
file_type_glob= "**/*.go"

# include specific 3rd party libs
vendor_include = sys.argv[2]

file_input = {
    "name":		"file_input",
    "desc": 		"Potentially Dangerous File Read Functions",
    "patterns": 	['ioutil.Readfile','os.OpenFile']
}

file_perm = {
    "name":		"file_perm",
    "desc":		"Potentially Dangerous Functions That Set File or Directory Permissions",
    "patterns":		['ioutil.WriteFile','os.OpenFile','os.Chmod','os.Mkdir','os.MkdirAll']
	
}

file_output = {
    "name":		"file_output",
    "desc":		"Potentially Dangerous File or Directory Write Functions",
    "patterns":		['ioutil.WriteFile','os.Mkdir','os.MkdirAll','os.Open','os.OpenFile','os.Create','os.NewFile']
}

path_manip = {
    "name":		"path_manip",
    "desc":		"Potentially Dangerous Path Manipulation Functions",
    "patterns":		['filepath.','ioutil.TempDir','ioutil.TempFile','ioutil.ReadDir','os.Mkdir','os.MkdirAll','os.Getwd','os.UserHomeDir','os.TempDir','os.SymLink']
}

code_exec = {
    "name":		"code_exec",
    "desc":		"Potentially Dangerous Code Execution Functions",
    "patterns":		['exec.Command','os.StartProcess','syscall.StartProcess','syscall.Exec','syscall.ForkExec']
} 

http_svr_config = {
    "name":		"http_svr_config",
    "desc":		"Potentially Dangerous HTTP Server Functions",
    "patterns":		['mux.NewRouter','http.NewServe','http.Serve','http.Listen']
}

http_tls_config = {
    "name":		"http_tls_config",
    "desc":		"Potentially Dangeours TLS Configuration Functions",
    "patterns":		['http.ListenAndServeTls','http.ServeTLS']
}

http_redir = {
    "name":		"http_redir",
    "desc":		"Potentially Dangerous HTTP Redirection Functions",
    "patterns":		['http.Redirect']
}

http_cookie = {
    "name":		"http_cookie",
    "desc":		"Potentially Dangerous HTTP Cookie Handling Functions",
    "patterns":		['http.Cookie','http.SetCookie','http.CookieJar']
}

http_client = {
    "name":		"http_client",
    "desc":		"Potentially Dangerous HTTP Client Functions to Check for SSRF or HPP",
    "patterns":		['http.Client','http.Do','http.Head','http.Get','http.Post','http.PostForm']
}

api_endpoint = {
    "name":		"api_endpoint",
    "desc":		"Potential API Endpoint",
    "patterns":		['/api/']
}

socket = {
    "name":		"socket",
    "desc":		"Potential Socket Connection",
    "patterns":		['net.Conn']
}

crypto = {
    "name":		"crypto",
    "desc":		"Potentially Dangerous Cryptographic Implementation",
    "patterns":		['pbkdf2.Key','aes.','cipher.','des.','dsa.','ecdsa.','elliptic.','hmac.','md5.','rand.','rc4.','rsa.','sha1.','sha265.','sha512.','tls.','x509.']
}

zip = {
    "name":		"zip",
    "desc":		"Potential Dangerous Use of Compression/Decompression",
    "patterns":		['zip.OpenReader','zip.NewWriter','zip.FileInfo']
}

xml = {
    "name":		"xml",
    "desc":		"Potentially Dangerous XML Processing",
    "patterns":		['xml.UnMarshal']
}


search_policy = [file_input,file_perm,file_output,path_manip,code_exec,http_svr_config,http_tls_config,http_redir,http_cookie,http_client,api_endpoint,socket,crypto,zip,xml]

# Normalize trailing path separator
if not ( search_path.endswith("/") or search_path.endswith('\\') ):
    search_path = search_path + "/"

search_path_glob = search_path + file_type_glob
temp_dir = tempfile.mkdtemp()

# TODO: Log results to sqlite file
#sqlite_results_file = temp_dir + "/results.sqlite"
#conn = sqlite3.connect(sqlite_results_file)
#c = conn.cursor()
#sqlfile = open('results_schema.sql', 'r')
#sql = sqlfile.read()
#sqlfile.close()
#c.executescript(sql)
#print("## Results are at:")
#print(sqlite_results_file)

finding_no = 0

# Main
for fname in glob.iglob(search_path_glob, recursive=True):
    # filter out test code
    if "testing.go" in fname or "/test" in fname or "_test.go" in fname:
        continue

    # filter out developer tools/scripts
    if "/dev-tools/" in fname:
        continue

    # filter out 3rd party libs with "exceptions"
    if "/vendor/" in fname and vendor_include not in fname:
        continue

    fo = open(fname)
    line = fo.readline()
    line_no = 1
    last_fname = ""
    last_index_lineno = ""
    while line != '' :
        # skip over comment lines
        if "// " not in line:
            for policy in search_policy:
                for search_str in policy["patterns"]:
                    index = line.find(search_str)
                    if (index != -1):

                        # only print filename on first iteration
                        if last_fname != fname:
                            print(os.path.relpath(fname, search_path) + ":")
                            finding_no += 1
                        last_fname = fname

                        # only print line,column,search policy, and code line on first iteration 
                        index_lineno = "    [" + str(line_no) + "," + str(index) + "]"
                        lineout = line + "\n\n"
                        if last_index_lineno != index_lineno:
                            print("    line, col: " + index_lineno) 
                            print("    search_policy: " + policy["name"])
                            print("    search_string: " + search_str)
                            print("    " + lineout)
                        last_index_lineno = index_lineno

                        # ToDo: Add INSERTs for new SQL schema
                        #encoded_line = base64.b64encode(line.encode("utf-8"))
                        #sql = "INSERT OR IGNORE INTO " + policy["name"] + " (desc,pattern,fname,line_no,col,line) VALUES(?,?,?,?,?,?)"
                        #args = (policy["desc"],search_str,fname,line_no,index,encoded_line)
                        #c.execute(sql,args)
        line = fo.readline()
        line_no += 1
    fo.close()
conn.commit()
conn.close()
#print("# of findings: " + str(finding_no))
