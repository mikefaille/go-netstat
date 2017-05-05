package gonetstat

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/mikefaille/yagt"
)


type Netstat struct {
	Proto               string
	RecvQ               string
	SendQ               string
	LocalAddress        net.TCPAddr
	ForeignAddress      net.TCPAddr
	State               string
	Pid                 string
	ProgramName         string
	IsConnectionUnbound bool
}

type Status int

// Méthode pour représenter un enum de state de connections
const (
	ESTABLISHED Status = iota
	SYN_SENT
	SYN_RECV
	FIN_WAIT1
	FIN_WAIT2
	TIME_WAIT
	CLOSE
	CLOSE_WAIT
	LAST_ACK
	LISTEN
	CLOSING
	UNKNOWN
)

var ConnStatus = [...]string{
	ESTABLISHED: "ESTABLISHED",
	SYN_SENT:    "SYN_SENT",
	FIN_WAIT1:   "FIN_WAIT1",
	FIN_WAIT2:   "FIN_WAIT2",
	TIME_WAIT:   "TIME_WAIT",
	CLOSE:       "CLOSE",
	CLOSE_WAIT:  "CLOSE_WAIT",
	LAST_ACK:    "LAST_ACK",
	LISTEN:      "LISTEN",
	CLOSING:     "CLOSING",
	UNKNOWN:     "UNKNOWN",
}

func GetOutputv2() ([]Netstat, error) {
	yagt.Enter()
	defer yagt.Exit(time.Now())

	linesOutput := make([]Netstat, 0)

	cmdName := "/bin/netstat"
	cmdArgs := []string{"-antp"}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error creating StdoutPipe for netstat", err)
		return nil, err
	}

	scanner := bufio.NewScanner(cmdReader)
	go func() {

		// Skip 2 next lines
		if !(scanner.Scan() && scanner.Scan()) {
			log.Fatalln("netstat output is empty")
		}

		for scanner.Scan() {

			line := scanner.Text()

			splitted := strings.Fields(line)

			if len(splitted) < 6 {
				log.Println("GetOutputv2 Error: ", splitted)
			} else {

				localAddr, err := parseStrAddr(splitted[3])
				if err != nil {
					log.Fatalln("Netstat. Can't parse source address: "+splitted[3], err)

				}

				ForeignAddr, err := parseStrAddr(splitted[4])
				if err != nil {
					log.Fatalln("Netstat. Can't parse destination address: "+splitted[3], err)
				}

				pid := ""
				programName := ""

				isConnectionUnbound := false
				switch {
				case splitted[6] == "-":
					pid = "-"
					programName = "-"

					if os.Getenv("USER") == "root" {
						isConnectionUnbound = true
					}
					break
				case strings.Contains(splitted[6], "/"):
					pidNProgramName := strings.SplitN(splitted[6], "/", 2)
					pid = pidNProgramName[0]
					programName = pidNProgramName[1]
					break
				default:

					break
				}

				netstatStruct := Netstat{
					Proto:               splitted[0],
					RecvQ:               splitted[1],
					SendQ:               splitted[2],
					LocalAddress:        localAddr,
					ForeignAddress:      ForeignAddr,
					State:               splitted[5],
					Pid:                 pid,
					ProgramName:         programName,
					IsConnectionUnbound: isConnectionUnbound,
				}

				linesOutput = append(linesOutput, netstatStruct)
			}

		}

	}()

	err = cmd.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting netstat", err)
		return nil, err
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for netstat", err)
		return linesOutput, err
	}
	return linesOutput, nil

}

// deprecated
func GetOutput() string {

	lineOutput := make([]string, 0)

	cmdName := "/bin/netstat"
	cmdArgs := []string{"-antp"}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmdReader, err := cmd.StdoutPipe()
	if err != nil {
		log.Panic("Error creating StdoutPipe for Cmd", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(cmdReader)
	go func() {
		for scanner.Scan() {
			line := scanner.Text()
			lineOutput = append(lineOutput, line)

		}
	}()

	err = cmd.Start()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error starting Cmd", err)
		os.Exit(1)
	}

	err = cmd.Wait()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error waiting for Cmd", err)
		os.Exit(1)
	}

	return strings.Join(lineOutput, "\n")
}

func Contain(strToFilter string, filters ...string) (output string, err error) {

	lineOutput := make([]string, 0)

	b := bytes.NewBufferString(strToFilter)

	scanner := bufio.NewScanner(b)
	for scanner.Scan() {
		isContained := true
		noutLine := scanner.Text()
		for _, filter := range filters {

			if !strings.Contains(noutLine, filter) {
				isContained = false
			}

		}
		if isContained == true {
			lineOutput = append(lineOutput, noutLine)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
	output = strings.Join(lineOutput, "\n")
	return
}

func NotContain(strToFilter string, filters ...string) (output string, err error) {

	lineOutput := make([]string, 0)

	b := bytes.NewBufferString(strToFilter)

	scanner := bufio.NewScanner(b)
	for scanner.Scan() {
		isContained := false
		noutLine := scanner.Text()
		for _, filter := range filters {

			if strings.Contains(noutLine, filter) {
				isContained = true
			}

		}
		if isContained == false {
			lineOutput = append(lineOutput, noutLine)
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
	output = strings.Join(lineOutput, "\n")
	return
}

func LineCount(stringToCountLine string, filters ...string) int {

	counter := 0

	b := bytes.NewBufferString(stringToCountLine)

	scanner := bufio.NewScanner(b)
	for scanner.Scan() {
		scanner.Text()
		counter++
		// do something with your line
	}

	return counter
}

func parseStrAddr(addrStr string) (newAddr net.TCPAddr, err error) {
	var ipStr string
	var portStr string
	var localPort int
	if strings.Count(addrStr, ":") > 1 {
		hostPortSeparatorIdx := strings.LastIndex(addrStr, ":")
		ipStr = addrStr[:hostPortSeparatorIdx]
		portStr = addrStr[hostPortSeparatorIdx+1:]

	} else {
		ipStr, portStr, err = net.SplitHostPort(addrStr)
		if err != nil {
			log.Fatalln("SplitHostPort error :", err)
		}

	}

	localIP := net.ParseIP(ipStr)

	if localIP == nil {
		err = fmt.Errorf("userip: %q is not IP:port", addrStr)
	}
	if portStr == "*" {
		localPort = 0
	} else {
		localPort, err = strconv.Atoi(portStr)
		if err != nil {
			log.Fatalln("Parse port: ", err)
		}

	}

	newAddr = net.TCPAddr{IP: localIP, Port: localPort}

	return newAddr, err
}
