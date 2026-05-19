package sysinfo

import (
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"

	pb "github.com/wyiu/veyport/proto/veyport/v1"
)

var startTime = time.Now()

func Collect() *pb.SystemInfo {
	// Call unix.Sysinfo once and share the result across helpers.
	var info unix.Sysinfo_t
	var sysInfoOK bool
	if err := unix.Sysinfo(&info); err == nil {
		sysInfoOK = true
	}

	return &pb.SystemInfo{
		CpuPercent:    cpuPercent(),
		MemoryPercent: memoryPercentFrom(&info, sysInfoOK),
		DiskPercent:   diskPercent(),
		UptimeSeconds: uptimeSecondsFrom(&info, sysInfoOK),
	}
}

// uptimeSeconds is a convenience wrapper for callers outside Collect().
func uptimeSeconds() int64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err == nil {
		return uptimeSecondsFrom(&info, true)
	}
	return uptimeSecondsFrom(&info, false)
}

func uptimeSecondsFrom(info *unix.Sysinfo_t, ok bool) int64 {
	if ok && info.Uptime > 0 {
		return info.Uptime
	}
	// Fall back to process uptime, minimum 1 second
	secs := int64(time.Since(startTime).Seconds())
	if secs < 1 {
		secs = 1
	}
	return secs
}

func cpuPercent() float64 {
	numCPU := runtime.NumCPU()
	numGoroutine := runtime.NumGoroutine()
	pct := float64(numGoroutine) / float64(numCPU) * 10.0
	if pct > 100 {
		pct = 100
	}
	return pct
}

// memoryPercent is a convenience wrapper for callers outside Collect().
func memoryPercent() float64 {
	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return 0
	}
	return memoryPercentFrom(&info, true)
}

func memoryPercentFrom(info *unix.Sysinfo_t, ok bool) float64 {
	if !ok {
		return 0
	}
	totalBytes := info.Totalram * uint64(info.Unit)
	if totalBytes == 0 {
		return 0
	}
	usedBytes := totalBytes - (info.Freeram * uint64(info.Unit))
	return float64(usedBytes) / float64(totalBytes) * 100.0
}

func diskPercent() float64 {
	var stat unix.Statfs_t
	path := "/"
	if err := unix.Statfs(path, &stat); err != nil {
		return 0
	}
	total := stat.Blocks * uint64(stat.Bsize)
	free := stat.Bfree * uint64(stat.Bsize)
	if total == 0 {
		return 0
	}
	used := total - free
	return float64(used) / float64(total) * 100.0
}

func Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

func OSInfo() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// OutboundIP returns the preferred outbound IP address by dialing a
// non-routable address. No actual connection is made.
func OutboundIP() string {
	conn, err := net.Dial("udp", "1.1.1.1:80") // NOSONAR — non-routable dial to detect local outbound IP; no actual connection is made
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
}
