package main

import (
	"archive/tar"
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
)

// This is also in `executor/runtime/docker/docker.go`
const metatronContainerRunDir = "/titus/run/metatron"

func main() { // nolint: gocyclo
	tarF, err := os.Open(metatronContainerRunDir + "/app.tar")
	if err != nil {
		panic(err)
	}
	defer tarF.Close() // nolint: errcheck

	bufReader := bufio.NewReader(tarF)
	tarReader := tar.NewReader(bufReader)

	for {
		hdr, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			panic(err)
		}

		fileName := hdr.Name
		if !strings.HasPrefix(fileName, "/") {
			fileName = "/" + fileName
		}

		if hdr.Typeflag == tar.TypeDir {
			if err = os.MkdirAll(fileName, 0755); err != nil { // nolint: gosec
				panic(fmt.Errorf("Error creating directory %s: %+v", fileName, err))
			}

			continue
		}

		file, err := os.OpenFile(fileName, os.O_CREATE|os.O_WRONLY, 0444)
		if err != nil {
			panic(fmt.Errorf("Error opening file %s: %+v", fileName, err))
		}
		defer file.Close() // nolint: errcheck

		fileWriter := bufio.NewWriter(file)

		if _, err = io.Copy(fileWriter, tarReader); err != nil {
			panic(fmt.Errorf("Error writing tar contents to file %s: %+v", fileName, err))
		}

		if err = fileWriter.Flush(); err != nil {
			panic(fmt.Errorf("Error flushing file contents to file %s: %+v", fileName, err))
		}
	}
}
