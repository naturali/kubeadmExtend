package tools

import "github.com/golang/glog"

// CheckError Is Error
func CheckError(err error) {
	if err != nil {
		glog.Fatal(err.Error())
	}
}
