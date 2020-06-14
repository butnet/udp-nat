package server

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

func ParseUserList(userConfig string) (map[string]string, error) {
	file, err := os.Open(userConfig)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	users := make(map[string]string)

	lineNumber := 0
	reader := bufio.NewReader(file)
	var currLine []byte
	for {
		line, isPrefix, err := reader.ReadLine()
		if !isPrefix {
			lineNumber++
		}
		if err != nil {
			if err != io.EOF {
				return nil, err
			}
			if currLine == nil {
				currLine = line
			} else {
				currLine = append(currLine, line...)
			}
			if len(currLine) == 0 {
				break
			}
			i := bytes.IndexByte(currLine, ':')
			if i == -1 {
				return nil, errors.New(fmt.Sprintf("配置错误,没有密码,在行: %d", lineNumber))
			}
			users[string(currLine[0:i])] = string(currLine[i+1:])
			break
		}
		if isPrefix {
			if currLine == nil {
				currLine = line
			} else {
				currLine = append(currLine, line...)
			}
		} else {
			if currLine == nil {
				currLine = line
			} else {
				currLine = append(currLine, line...)
			}
			if len(currLine) == 0 {
				continue
			}
			i := bytes.IndexByte(currLine, ':')
			if i == -1 {
				return nil, errors.New(fmt.Sprintf("配置错误,没有密码,在行: %d", lineNumber))
			}
			users[string(currLine[0:i])] = string(currLine[i+1:])
			currLine = nil
		}
	}

	return users, nil
}
