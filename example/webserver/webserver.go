package main

import (
	"fmt"
	"net/http"
	"syscall"
	"unsafe"
)

func books(w http.ResponseWriter, req *http.Request) {
	filenamePtr, err := syscall.BytePtrFromString("/tmp/hooked_syscall_trigger")
	if err != nil {
		return
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_OPEN, uintptr(unsafe.Pointer(filenamePtr)), syscall.O_CREAT, 0755)
	if errno != 0 {
		return
	}
	defer syscall.Close(int(fd))

	fmt.Fprintf(w, `{"books": [{"id": 1, "author": "Charles Dickens", "title": "Oliver Twist"}, {"id": 2, "author": "William Golding", "title": "Lord of the Flies"}]}\n`)

}

func headers(w http.ResponseWriter, req *http.Request) {

	for name, headers := range req.Header {
		for _, h := range headers {
			fmt.Fprintf(w, "%v: %v\n", name, h)
		}
	}
}

func main() {
	http.HandleFunc("/books", books)
	http.HandleFunc("/headers", headers)

	fmt.Println("Server listening at 0.0.0.0:8090 ...")
	http.ListenAndServe(":8090", nil)
	return
}
