package main

//------------------------
// traceroute.go
// author: mohan chinnappan
//------------------------

import (
    "flag"
    "fmt"
    "html/template"
    "net"
    "os"
    "strings"
    "time"

    "golang.org/x/net/icmp"
    "golang.org/x/net/ipv4"
)

const (
    // ProtocolICMP is the protocol number for ICMP
    ProtocolICMP = 1
    // MaxHops is the maximum number of hops to trace
    MaxHops = 30
    // Timeout for each hop (in seconds)
    Timeout = 3 * time.Second
    // Number of packets to send per hop
    PacketsPerHop = 3
)

// HopResult represents the result of a single hop in the traceroute
type HopResult struct {
    HopNumber   int
    Addresses   []string
    Hostnames   []string
    RTTs        []string // Round-trip times in milliseconds (without "ms" suffix)
    TimedOut    bool
}

type TracerouteResults struct {
    Hostname      string
    IP            string
    Hops          []HopResult
    NetworkLatency string // Total network latency to the destination in ms
}

func main() {
    // Parse command-line flags
    hostname := flag.String("host", "google.com", "hostname to trace")
    outputFile := flag.String("output", "traceroute_results.html", "output HTML file")
    flag.Parse()

    // Resolve the destination hostname to an IP address
    dstIP, err := net.ResolveIPAddr("ip4", *hostname)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error resolving host %s: %v\n", *hostname, err)
        os.Exit(1)
    }

    fmt.Printf("Tracing route to %s [%s], %d hops max\n", *hostname, dstIP.String(), MaxHops)

    // Perform the traceroute and collect results
    results := TracerouteResults{
        Hostname: *hostname,
        IP:       dstIP.String(),
        Hops:     traceroute(dstIP),
    }

    // Calculate the network latency (RTT of the final hop to the destination)
    results.NetworkLatency = calculateNetworkLatency(results.Hops, dstIP.String())

    // Generate the HTML output
    err = generateHTML(results, *outputFile)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error generating HTML output: %v\n", err)
        os.Exit(1)
    }

    fmt.Printf("Traceroute results saved to %s\n", *outputFile)
}

func traceroute(dstIP *net.IPAddr) []HopResult {
    // Create a raw socket to send/receive ICMP packets
    conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
    if err != nil {
        fmt.Fprintf(os.Stderr, "Error creating raw socket: %v\n", err)
        os.Exit(1)
    }
    defer conn.Close()

    // Wrap the connection in an ipv4.PacketConn to set IP header options
    pconn := ipv4.NewPacketConn(conn)

    // Collect results for each hop
    var results []HopResult

    // Send packets with increasing TTL and listen for replies
    for ttl := 1; ttl <= MaxHops; ttl++ {
        // Set the TTL on the outgoing packets
        if err := pconn.SetTTL(ttl); err != nil {
            fmt.Fprintf(os.Stderr, "Error setting TTL: %v\n", err)
            os.Exit(1)
        }

        // Send multiple packets per hop and collect responses
        hopAddresses := make(map[string]struct{}) // To track unique addresses for this hop
        hopTimes := make([]time.Duration, 0, PacketsPerHop)
        responded := false

        fmt.Printf("Tracing hop %d...\n", ttl)
        for i := 0; i < PacketsPerHop; i++ {
            // Send an ICMP Echo Request
            start := time.Now()
            if err := sendICMP(pconn, dstIP, ttl, i); err != nil {
                fmt.Fprintf(os.Stderr, "Error sending ICMP packet: %v\n", err)
                continue
            }

            // Receive the ICMP reply
            replyIP, rtt, done, err := receiveICMP(pconn, start)
            if err != nil {
                continue
            }

            responded = true
            hopAddresses[replyIP] = struct{}{}
            hopTimes = append(hopTimes, rtt)

            // If we reached the destination, we can stop
            if done {
                break
            }
        }

        // Create a HopResult for this hop
        hop := HopResult{
            HopNumber: ttl,
            TimedOut:  !responded,
        }

        if responded {
            // Add unique IP addresses
            for ip := range hopAddresses {
                hop.Addresses = append(hop.Addresses, ip)
            }
            // Perform reverse DNS lookup for each IP address
            for _, ip := range hop.Addresses {
                fmt.Printf("Resolving hostname for IP %s...\n", ip)
                names, err := net.LookupAddr(ip)
                if err != nil || len(names) == 0 {
                    fmt.Printf("No hostname found for IP %s\n", ip)
                    hop.Hostnames = append(hop.Hostnames, "N/A")
                } else {
                    // Use the first hostname and trim trailing dot
                    hostname := strings.TrimSuffix(names[0], ".")
                    fmt.Printf("Hostname for IP %s: %s\n", ip, hostname)
                    hop.Hostnames = append(hop.Hostnames, hostname)
                }
            }
            // Convert RTTs to strings (in milliseconds, without "ms" suffix)
            for _, rtt := range hopTimes {
                hop.RTTs = append(hop.RTTs, fmt.Sprintf("%.2f", float64(rtt)/float64(time.Millisecond)))
            }
        } else {
            hop.Addresses = []string{"*"}
            hop.Hostnames = []string{"*"}
            hop.RTTs = []string{"*", "*", "*"}
        }

        results = append(results, hop)

        // If we reached the destination, stop tracing
        if responded && len(hopAddresses) == 1 {
            _, isDst := hopAddresses[dstIP.String()]
            if isDst {
                break
            }
        }
    }

    return results
}

func sendICMP(conn *ipv4.PacketConn, dstIP *net.IPAddr, ttl, seq int) error {
    // Create an ICMP Echo Request message
    msg := icmp.Message{
        Type: ipv4.ICMPTypeEcho,
        Code: 0,
        Body: &icmp.Echo{
            ID:   os.Getpid() & 0xffff, // Use process ID as the identifier
            Seq:  seq,
            Data: []byte("SF-UTILS-TRACEROUTE"),
        },
    }

    // Marshal the ICMP message into bytes
    data, err := msg.Marshal(nil)
    if err != nil {
        return fmt.Errorf("error marshaling ICMP message: %v", err)
    }

    // Send the packet to the destination
    _, err = conn.WriteTo(data, nil, &net.IPAddr{IP: dstIP.IP})
    if err != nil {
        return fmt.Errorf("error sending ICMP packet: %v", err)
    }

    return nil
}

func receiveICMP(conn *ipv4.PacketConn, start time.Time) (string, time.Duration, bool, error) {
    // Set a timeout for receiving the reply
    conn.SetReadDeadline(time.Now().Add(Timeout))

    // Buffer to store the incoming packet
    buf := make([]byte, 1500)

    // Read the reply
    n, _, peer, err := conn.ReadFrom(buf)
    if err != nil {
        if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
            return "", 0, false, nil // Timeout, no reply
        }
        return "", 0, false, fmt.Errorf("error receiving ICMP packet: %v", err)
    }

    // Calculate round-trip time
    rtt := time.Since(start)

    // Parse the ICMP reply
    msg, err := icmp.ParseMessage(ProtocolICMP, buf[:n])
    if err != nil {
        return "", 0, false, fmt.Errorf("error parsing ICMP message: %v", err)
    }

    // Check the type of ICMP message
    switch msg.Type {
    case ipv4.ICMPTypeTimeExceeded:
        // TTL exceeded, this is an intermediate hop
        return peer.String(), rtt, false, nil
    case ipv4.ICMPTypeEchoReply:
        // Echo Reply, this is the destination
        if echo, ok := msg.Body.(*icmp.Echo); ok {
            if echo.ID == os.Getpid()&0xffff {
                return peer.String(), rtt, true, nil
            }
        }
    }

    return "", 0, false, nil // Ignore other ICMP messages
}

func calculateNetworkLatency(hops []HopResult, dstIP string) string {
    // If there are no hops or the last hop didn't respond, return "N/A"
    if len(hops) == 0 {
        return "N/A (no hops recorded)"
    }

    // Find the last hop that responded
    var lastHop *HopResult
    for i := len(hops) - 1; i >= 0; i-- {
        if !hops[i].TimedOut {
            lastHop = &hops[i]
            break
        }
    }

    // If no hops responded, return "N/A"
    if lastHop == nil {
        return "N/A (no response from any hop)"
    }

    // Check if the last hop's address matches the destination IP
    for _, addr := range lastHop.Addresses {
        if addr == dstIP {
            // Use the first RTT value from the last hop as the network latency
            return fmt.Sprintf("%s ms", lastHop.RTTs[0])
        }
    }

    // If the last hop isn't the destination, return "N/A"
    return "N/A (destination not reached)"
}

func generateHTML(results TracerouteResults, outputFile string) error {
    // Define the HTML template
    const htmlTemplate = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Traceroute Results - {{.Hostname}}</title>
  <link href="https://cdnjs.cloudflare.com/ajax/libs/tailwindcss/2.2.19/tailwind.min.css" rel="stylesheet">
  <!-- Add DataTables CSS -->
  <link rel="stylesheet" href="https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css">
  <!-- Add DataTables Buttons CSS for CSV export -->
  <link rel="stylesheet" href="https://cdn.datatables.net/buttons/2.4.2/css/buttons.dataTables.min.css">
  <style>
    body {
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    main {
      flex: 1;
    }
  </style>
</head>
<body class="bg-gray-100 font-sans p-4">
  <div class="container mx-auto max-w-4xl">
    <!-- Header -->
    <header class="bg-blue-500 text-white p-4 rounded-md shadow mb-4">
      <h1 class="text-2xl font-semibold">Traceroute Results</h1>
      <p class="text-sm">Tracing route to {{.Hostname}} [{{.IP}}]</p>
    </header>

    <!-- Traceroute Results Table -->
    <section class="mb-8">
      <p class="text-sm text-gray-600 mb-2">Round Trip timings are in milliseconds (ms). If the value is '*', the host is not reachable.</p>
      <div class="overflow-x-auto">
        <table id="tracerouteTable" class="display w-full">
          <thead>
            <tr>
              <th>Hop</th>
              <th>Addresses</th>
              <th>Hostnames</th>
              <th>RTT 1</th>
              <th>RTT 2</th>
              <th>RTT 3</th>
            </tr>
          </thead>
          <tbody>
            {{range .Hops}}
            <tr>
              <td>{{.HopNumber}}</td>
              <td>{{range $i, $addr := .Addresses}}{{if $i}}, {{end}}{{$addr}}{{end}}</td>
              <td>{{range $i, $name := .Hostnames}}{{if $i}}, {{end}}{{$name}}{{end}}</td>
              <td>{{index .RTTs 0}}</td>
              <td>{{if gt (len .RTTs) 1}}{{index .RTTs 1}}{{else}}*{{end}}</td>
              <td>{{if gt (len .RTTs) 2}}{{index .RTTs 2}}{{else}}*{{end}}</td>
            </tr>
            {{end}}
          </tbody>
        </table>
      </div>
      <!-- Network Latency KPI -->
      <div class="mt-4 bg-green-100 border-l-4 border-green-500 text-green-700 p-4 rounded-md shadow-lg">
        <p class="text-lg font-semibold">Total Network Latency to Destination</p>
        <p class="text-3xl font-bold">{{.NetworkLatency}}</p>
      </div>
    </section>

    <!-- Footer -->
    <footer class="mt-4 text-center text-gray-500 text-sm">
      <p>Made with ❤️ in <a href="https://en.wikipedia.org/wiki/New_Hampshire" target="_blank" class="text-blue-500 hover:underline">New Hampshire</a>
      by <a href="https://mohan-chinnappan-n.github.io/about/cv.html" target="_blank" class="text-blue-500 hover:underline">mc</a></p>
      <p>© 2025 Traceroute Tool</p>
    </footer>
  </div>

  <!-- Add jQuery and DataTables JS -->
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script src="https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js"></script>
  <!-- Add DataTables Buttons JS for CSV export -->
  <script src="https://cdn.datatables.net/buttons/2.4.2/js/dataTables.buttons.min.js"></script>
  <script src="https://cdn.datatables.net/buttons/2.4.2/js/buttons.html5.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js"></script>

  <script>
    $(document).ready(function() {
      $('#tracerouteTable').DataTable({
        paging: true,
        searching: true,
        ordering: true,
        pageLength: 10,
        lengthChange: true,
        lengthMenu: [ [10, 25, 50, 100], [10, 25, 50, 100] ], // Explicitly define page size options
        info: true,
        autoWidth: false,
        dom: 'lBfrtip', // Ensure 'l' (length menu) and 'B' (buttons) are included in the layout
        buttons: [
          {
            extend: 'csv',
            text: 'Download CSV',
            filename: 'traceroute_results',
            exportOptions: {
              modifier: {
                search: 'none' // Export all data, ignoring search filters
              }
            }
          }
        ]
      });
    });
  </script>
</body>
</html>
`

    // Parse the HTML template
    tmpl, err := template.New("traceroute").Parse(htmlTemplate)
    if err != nil {
        return fmt.Errorf("error parsing HTML template: %v", err)
    }

    // Create the output file
    file, err := os.Create(outputFile)
    if err != nil {
        return fmt.Errorf("error creating output file: %v", err)
    }
    defer file.Close()

    // Execute the template with the results
    err = tmpl.Execute(file, results)
    if err != nil {
        return fmt.Errorf("error executing template: %v", err)
    }

    return nil
}
