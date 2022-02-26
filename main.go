package main

import (
    "fmt"
    "net/http"
    "net/http/httputil"
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

    http.HandleFunc("/hello", hello)
    http.HandleFunc("/headers", headers)

    http.ListenAndServe(":8090", nil)
}
