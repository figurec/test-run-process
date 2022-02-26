package main

import (
    "fmt"
    "net/http"
    "net/http/httputil"
    "os"
)

func hello(w http.ResponseWriter, req *http.Request) {
res, err := httputil.DumpRequest(req, true)  
 if err != nil {  
   //log.Fatal(err)  
}  
fmt.Print(string(res))
  
    fmt.Fprintf(w, "hello\n")
}

func headers(w http.ResponseWriter, req *http.Request) {

    for name, headers := range req.Header {
        for _, h := range headers {
            fmt.Fprintf(w, "%v: %v\n", name, h)
        }
    }
}

func main() {
    port, ok := os.LookupEnv("PORT")
	if !ok {
		port = "8080"
	}
    http.HandleFunc("/", hello)
    http.HandleFunc("/headers", headers)

    http.ListenAndServe(":"+port, nil)
}
