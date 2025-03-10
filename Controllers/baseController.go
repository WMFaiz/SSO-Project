package Controller

import (
	"net/http"
)

type Controller struct {
}

// constant list of the installation progress status
const (
	STATUS_IN_PROGRESS = "In-Progress"
	STATUS_NOT_STARTED = "Not-Started"
)

func WriteHTTPSuccessResponse(w http.ResponseWriter, data []byte) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	w.Write(data)
	return
}
func WriteHTTPError(w http.ResponseWriter, errData string, httpErrCode int) {
	http.Error(w, errData, httpErrCode)
}
