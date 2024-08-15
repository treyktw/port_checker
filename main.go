package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

type Port struct {
	Name     string `json:"name"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type CommonPorts struct {
	Ports []Port `json:"common_ports"`
}

type ScanResult struct {
	IP     string `json:"ip"`
	Port   Port   `json:"port"`
	Status string `json:"status"`
}

var (
	scanProgress struct {
		Total     int  `json:"total"`
		Current   int  `json:"current"`
		IsRunning bool `json:"isRunning"`
		sync.Mutex
	}
	resultChan = make(chan ScanResult, 100)
)

func main() {
	r := gin.Default()

	r.LoadHTMLGlob("templates/*")
	r.Static("/static", "./static")

	r.GET("/", func(c *gin.Context) {
		c.HTML(200, "index.html", gin.H{})
	})

	r.POST("/scan", handleScan)
	r.GET("/events", handleSSE)

	r.Run(":3030")
}

func handleScan(c *gin.Context) {
	scanProgress.Lock()
	if scanProgress.IsRunning {
		scanProgress.Unlock()
		c.JSON(400, gin.H{"message": "Scan already in progress"})
		return
	}
	scanProgress.IsRunning = true
	scanProgress.Unlock()

	customIPs := c.PostForm("customIPs")
	ips := getLocalIPs()
	if customIPs != "" {
		ips = append(ips, strings.Split(customIPs, ",")...)
	}
	commonPorts := loadCommonPorts()

	scanProgress.Total = len(ips) * len(commonPorts)
	scanProgress.Current = 0

	go scanPorts(ips, commonPorts)

	c.JSON(200, gin.H{"message": "Scan started"})
}

func handleSSE(c *gin.Context) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Transfer-Encoding", "chunked")

	clientGone := c.Writer.CloseNotify()

	for {
		select {
		case result, ok := <-resultChan:
			if !ok {
				c.SSEvent("complete", "Scan complete")
				return
			}
			data, _ := json.Marshal(result)
			c.SSEvent("message", string(data))
			c.Writer.Flush()
		case <-clientGone:
			return
		}
	}
}

func scanPorts(ips []string, ports []Port) {
	defer close(resultChan)
	defer func() {
		scanProgress.Lock()
		scanProgress.IsRunning = false
		scanProgress.Unlock()
	}()

	for _, ip := range ips {
		for _, port := range ports {
			address := fmt.Sprintf("%s:%d", ip, port.Port)
			conn, err := net.DialTimeout("tcp", address, 200*time.Millisecond)
			status := "closed"
			if err == nil {
				conn.Close()
				status = "open"
			}
			resultChan <- ScanResult{IP: ip, Port: port, Status: status}

			scanProgress.Lock()
			scanProgress.Current++
			scanProgress.Unlock()
		}
	}
}

func getLocalIPs() []string {
	cmd := exec.Command("ipconfig", "/all")
	output, err := cmd.Output()
	if err != nil {
		fmt.Println("Error executing ipconfig:", err)
		return nil
	}

	re := regexp.MustCompile(`IPv4 Address[.\s]+: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)`)
	matches := re.FindAllStringSubmatch(string(output), -1)

	var ips []string
	for _, match := range matches {
		ips = append(ips, match[1])
	}

	return ips
}

func loadCommonPorts() []Port {
	data, err := ioutil.ReadFile("common_ports.json")
	if err != nil {
		fmt.Println("Error reading common_ports.json:", err)
		return nil
	}

	var commonPorts CommonPorts
	err = json.Unmarshal(data, &commonPorts)
	if err != nil {
		fmt.Println("Error parsing JSON:", err)
		return nil
	}

	return commonPorts.Ports
}
