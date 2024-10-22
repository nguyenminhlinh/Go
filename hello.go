// package main

// import (
// 	"bufio"
// 	"context"
// 	"fmt"
// 	"log"
// 	"os"
// 	"sync"
// 	"time"

// 	"github.com/miekg/dns"

// 	"github.com/owasp-amass/amass/v3/config"
// 	"github.com/owasp-amass/amass/v3/enum"
// 	"github.com/owasp-amass/amass/v3/netmap"
// 	"github.com/owasp-amass/amass/v3/systems"
// )

// func dig(domain string, qtype uint16) {
// 	// Create a DNS message
// 	msg := new(dns.Msg)
// 	msg.SetQuestion(dns.Fqdn(domain), qtype)
// 	msg.RecursionDesired = true

// 	// Select the DNS server to query
// 	dnsServer := "8.8.8.8:53" //Use Google DNS

// 	// Create a client to send DNS requests
// 	client := new(dns.Client)
// 	client.Timeout = 5 * time.Second

// 	// Send DNS requests
// 	response, rtt, err := client.Exchange(msg, dnsServer)
// 	if err != nil {
// 		fmt.Printf("Error: %v\n", err)
// 		return
// 	}

// 	// Check DNS status code (Rcode)
// 	fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n", dns.RcodeToString[response.Rcode], response.Id)
// 	fmt.Printf(";; query time: %v msec\n", rtt.Milliseconds())
// 	fmt.Println(response.Answer)
// 	// Print the response if the status is NOERROR
// 	if response.Rcode == dns.RcodeSuccess {
// 		//fmt.Println(response.Answer)
// 		// for _, answer := range response.Answer {
// 		// 	fmt.Println(answer.String())
// 		// }
// 	} else {
// 		fmt.Printf("Query failed with status: %s\n", dns.RcodeToString[response.Rcode])
// 	}
// }

// func test(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, count *int, mu *sync.Mutex) {
// 	defer wg.Done()
// 	for {
// 		time.Sleep(1 * time.Second)
// 		select {
// 		case <-ctx.Done():
// 			mu.Lock()
// 			*count++
// 			fmt.Println("Context cancelled, stopping file test.")
// 			// Nếu nhận tín hiệu hủy từ context, đóng semaphore và thoát

// 			fmt.Println(*count)
// 			if *count == 10 {
// 				close(results)
// 				fmt.Println("stopping file test.")
// 				for len(semaphore) > 0 {
// 					<-semaphore // Đọc và bỏ qua dữ liệu cho đến khi channel trống
// 				}

// 			}
// 			mu.Unlock()
// 			return
// 		default:
// 			subdomain, ok := <-semaphore
// 			fmt.Println("Error reading file:")
// 			if !ok {
// 				return
// 			} else {
// 				results <- subdomain + "*"
// 			}
// 		}
// 	}
// }

// func BruteDomainDNS(ctx context.Context, cancel context.CancelFunc, wordlist string) {
// 	//Đọc wordlists từ file
// 	var wg sync.WaitGroup
// 	var count int
// 	var mu sync.Mutex
// 	semaphore := make(chan string, 10)
// 	results := make(chan string, 10)
// 	wg.Add(1)
// 	go readFiles(ctx, &wg, wordlist, semaphore)
// 	for i := 0; i < 10; i++ {
// 		wg.Add(1)
// 		go test(ctx, &wg, semaphore, results, &count, &mu)
// 	}

// 	wg.Add(1)
// 	go writeFiles(ctx, &wg, results, "linh.txt")
// 	wg.Wait()
// }

// // func output(ctx context.Context, wg *sync.WaitGroup, results chan string) {
// // 	defer wg.Done()
// // 	for {
// // 		time.Sleep(1 * time.Second)
// // 		select {
// // 		case result, ok := <-results:
// // 			if !ok {
// // 				fmt.Println("hết write")
// // 				//close(results)
// // 				return
// // 			}
// // 			fmt.Println("out", result)
// // 		case <-ctx.Done(): // Nếu nhận được tín hiệu hủy từ context
// // 			fmt.Println("Context cancelled, stopping file write.")
// // 			return
// // 		}
// // 	}
// // }

// func main() {

// 	// if len(os.Args) < 2 {
// 	// 	fmt.Println("Usage: go-dig <domain>")
// 	// 	os.Exit(1)
// 	// }

// 	// domain := os.Args[1]

// 	// // Truy vấn A record
// 	// fmt.Printf("A Record cho %s:\n", domain)
// 	// dig(domain, dns.TypeA)

// 	// // Truy vấn MX record
// 	// fmt.Printf("\nMX Record cho %s:\n", domain)
// 	// dig(domain, dns.TypeMX)

// 	// // Truy vấn NS record
// 	// fmt.Printf("\nNS Record cho %s:\n", domain)
// 	// dig(domain, dns.TypeNS)

// 	// // Truy vấn CNAME record
// 	// fmt.Printf("\nCNAME Record cho %s:\n", domain)
// 	// dig(domain, dns.TypeCNAME)

// 	// // Truy vấn SOA record
// 	// fmt.Printf("\nSOA Record cho %s:\n", domain)
// 	// dig(domain, dns.TypeSOA)

// 	// fmt.Printf("\nTXT Record cho %s:\n", domain)
// 	// dig(domain, dns.TypeTXT)
// 	// ctx, cancel := context.WithCancel(context.Background())
// 	// defer cancel()

// 	// // Bắt tín hiệu Ctrl+C từ người dùng
// 	// c := make(chan os.Signal, 1)
// 	// signal.Notify(c, os.Interrupt, syscall.SIGTERM)
// 	// go func() {
// 	// 	<-c
// 	// 	fmt.Println("Received Ctrl+C, canceling all tasks...")
// 	// 	cancel() // Hủy tất cả các goroutine đang chạy
// 	// }()

// 	// var wg sync.WaitGroup
// 	// wg.Add(1)
// 	// go func() {
// 	// 	BruteDomainDNS(ctx, cancel, "C:\\Users\\minhl\\recon\\src\\data\\input\\combined_subdomains.txt")
// 	// 	fmt.Println("17")
// 	// 	wg.Done()
// 	// }()

// 	// wg.Wait()
// 	// Tạo cấu hình cho Amass
// 	cfg := config.NewConfig()
// 	cfg.AddDomain("example.com") // Thêm domain cần kiểm tra

// 	// Khởi tạo hệ thống của Amass
// 	sys, err := systems.NewLocalSystem(cfg)
// 	if err != nil {
// 		log.Fatalf("Failed to create system: %v", err)
// 	}
// 	defer sys.Shutdown()

// 	// Khởi tạo đồ thị mạng
// 	graph := netmap.NewGraph(cfg)

// 	// Tạo đối tượng Amass enumeration
// 	e := enum.NewEnumeration(cfg, sys, graph)

// 	// Khởi động Amass enumeration
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	// Channel để nhận kết quả từ quá trình enumeration
// 	results := make(chan *enum.Output, 100)

// 	// Bắt đầu thu thập dữ liệu từ channel
// 	go func() {
// 		for result := range results {
// 			fmt.Printf("Subdomain found: %s\n", result.Name)
// 		}
// 	}()

// 	// Chạy quá trình enumeration và gửi kết quả vào channel
// 	if err := e.Start(ctx, results); err != nil {
// 		log.Fatalf("Failed to start Amass enumeration: %v", err)
// 	}

// 	// Đợi quá trình hoàn thành (tùy vào yêu cầu có thể thêm logic để chờ)
// 	<-ctx.Done()

// }
// package main

// import (
// 	"context"
// 	"fmt"
// 	"log"
// 	"os"
// 	"sync"
// 	"time"

// 	"github.com/caffix/netmap"
// 	"github.com/caffix/stringset"
// 	"github.com/fatih/color"
// 	"github.com/owasp-amass/amass/v4/datasrcs"
// 	"github.com/owasp-amass/amass/v4/enum"
// 	"github.com/owasp-amass/amass/v4/systems"
// 	"github.com/owasp-amass/asset-db/types"
// 	"github.com/owasp-amass/config/config"
// 	oam "github.com/owasp-amass/open-asset-model"
// )

// var (
// 	// Colors used to ease the reading of program output
// 	green   = color.New(color.FgHiGreen).SprintFunc()
// 	magenta = color.New(color.FgHiMagenta).SprintFunc()
// 	white   = color.New(color.FgHiWhite).SprintFunc()
// )

// // func extractAssetName(a *types.Asset) string {
// // 	var result string

// // 	// In ra chi tiết của asset để kiểm tra
// // 	fmt.Printf("Asset Type: %v, Asset Data: %v\n", a.Asset.AssetType(), a.Asset)

// // 	switch a.Asset.AssetType() {
// // 	case oam.FQDN:
// // 		if fqdn, ok := a.Asset.(domain.FQDN); ok {
// // 			result = fqdn.Name + " (FQDN)"
// // 		}
// // 	case oam.IPAddress:
// // 		if ip, ok := a.Asset.(network.IPAddress); ok {
// // 			result = ip.Address.String() + " (IPAddress)"
// // 		}
// // 	case oam.ASN:
// // 		if asn, ok := a.Asset.(network.AutonomousSystem); ok {
// // 			result = strconv.Itoa(asn.Number) + " (ASN)"
// // 		}
// // 	case oam.RIROrg:
// // 		if rir, ok := a.Asset.(network.RIROrganization); ok {
// // 			result = rir.RIRId + " " + rir.Name + " (RIROrganization)"
// // 		}
// // 	case oam.Netblock:
// // 		if nb, ok := a.Asset.(network.Netblock); ok {
// // 			result = nb.Cidr.String() + " (Netblock)"
// // 		}
// // 	default:
// // 		// Nếu asset type không khớp, hiển thị loại asset chưa được nhận dạng
// // 		result = fmt.Sprintf("Unrecognized Asset Type: %v", a.Asset.AssetType())
// // 	}

// // 	// Kiểm tra nếu kết quả là chuỗi rỗng và in ra thông báo cảnh báo
// // 	if result == "" {
// // 		result = "Unknown Asset Information"
// // 	}

// // 	return result
// // }

// func NewOutput(ctx context.Context, g *netmap.Graph, e *enum.Enumeration, filter *stringset.Set, since time.Time) []string {
// 	var output []string

// 	// Make sure a filter has been created
// 	if filter == nil {
// 		filter = stringset.New()
// 		defer filter.Close()
// 	}

// 	var assets []*types.Asset
// 	for _, atype := range []oam.AssetType{oam.FQDN, oam.IPAddress, oam.Netblock, oam.ASN} {
// 		if a, err := g.DB.FindByType(atype, since.UTC()); err == nil {
// 			assets = append(assets, a...)
// 		}
// 	}
// 	arrow := white("-->")
// 	start := e.Config.CollectionStartTime.UTC()
// 	for _, from := range assets {
// 		// fmt.Printf("Asset Type: %v, Asset Data: %v\n", from.Asset.AssetType(), from.Asset)
// 		fromstr := fmt.Sprintf("%v", from.Asset.AssetType()) + "" + fmt.Sprintf("%v", from.Asset)
// 		if rels, err := g.DB.OutgoingRelations(from, start); err == nil {
// 			for _, rel := range rels {
// 				lineid := from.ID + rel.ID + rel.ToAsset.ID
// 				if filter.Has(lineid) {
// 					continue
// 				}
// 				if to, err := g.DB.FindById(rel.ToAsset.ID, start); err == nil {
// 					tostr := fmt.Sprintf("%v", to.Asset.AssetType()) + " " + fmt.Sprintf("%v", to.Asset)
// 					output = append(output, fmt.Sprintf("%s %s %s %s %s", fromstr, arrow, magenta(rel.Type), arrow, tostr))
// 					filter.Insert(lineid)
// 				}
// 			}
// 		}
// 	}

// 	return output
// }

// func processOutput(ctx context.Context, ctx1 context.Context, g *netmap.Graph, e *enum.Enumeration, outputs chan string, done chan struct{}, wg *sync.WaitGroup) {
// 	defer wg.Done()
// 	defer close(outputs)

// 	// This filter ensures that we only get new names
// 	known := stringset.New()
// 	defer known.Close()

// 	// The function that obtains output from the enum and puts it on the channel
// 	extract := func(since time.Time) {
// 		for _, o := range NewOutput(ctx, g, e, known, since) {
// 			fmt.Println(o)
// 		}
// 	}

// 	t := time.NewTimer(10 * time.Second)
// 	defer t.Stop()
// 	last := e.Config.CollectionStartTime
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			extract(last)
// 			return
// 		case <-done:
// 			extract(last)
// 			return
// 		case <-t.C:
// 			next := time.Now()
// 			extract(last)
// 			t.Reset(10 * time.Second)
// 			last = next
// 		}
// 	}
// }

// func amass() {
// 	// Tạo cấu hình cho Amass
// 	cfg := config.NewConfig()
// 	cfg.Verbose = true // Bật chế độ Verbose để theo dõi quá trình
// 	// Check if a configuration file was provided, and if so, load the settings
// 	if err := config.AcquireConfig("D:/OneDrive - zb87w/STUDY/Tuhoc/Go/examples", "D:/OneDrive - zb87w/STUDY/Tuhoc/Go/examples/config.yaml", cfg); err != nil {
// 		log.Fatalf("Failed to configuration file: %v", err)
// 	}
// 	cfg.AddDomain("hackerone.com") // Thêm domain cần kiểm tra
// 	//fmt.Println(cfg.Domains())
// 	// Khởi tạo hệ thống của Amass
// 	//fmt.Printf("Config Loaded: %+v\n", cfg)

// 	sys, err := systems.NewLocalSystem(cfg)
// 	if err != nil {
// 		log.Fatalf("Failed to create system: %v", err)
// 	}
// 	defer func() { _ = sys.Shutdown() }()

// 	if err := sys.SetDataSources(datasrcs.GetAllSources(sys)); err != nil {
// 		fmt.Fprintf(color.Error, "%v\n", err)
// 		os.Exit(1)
// 	}
// 	// Setup the new enumeration
// 	e := enum.NewEnumeration(cfg, sys, sys.GraphDatabases()[0])
// 	if e == nil {
// 		fmt.Fprintf(color.Error, "%s\n", "Failed to setup the enumeration")
// 		os.Exit(1)
// 	}
// 	var wg sync.WaitGroup
// 	var outChans chan string
// 	done := make(chan struct{})
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
// 	wg.Add(1)
// 	go processOutput(ctx, sys.GraphDatabases()[0], e, outChans, done, &wg)
// 	// Khởi động Amass enumeration

// 	fmt.Println("Starting Amass enumeration...")
// 	// Chạy quá trình enumeration và gửi kết quả vào channel
// 	if err := e.Start(ctx); err != nil {
// 		log.Fatalf("Failed to start Amass enumeration: %v", err)
// 	}

// 	// Đợi quá trình hoàn thành (tùy vào yêu cầu có thể thêm logic để chờ)
// 	close(done)
// 	wg.Wait()
// 	fmt.Fprintf(color.Error, "\n%s\n", green("The enumeration has finished"))
// }

//	func main() {
//		go amass()
//	}
// package main

// import (
// 	"context"
// 	"fmt"
// 	"time"
// )

// func extract(last time.Time) {
// 	// Xử lý kết quả hoặc công việc cần làm
// 	fmt.Println("Extracting data since:", last)
// }

// func main() {
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()

// 	timeout := 1 * time.Minute
// 	ctxTimeout, cancelTimeout := context.WithTimeout(ctx, timeout)
// 	defer cancelTimeout()

// 	ticker := time.NewTicker(10 * time.Second)
// 	defer ticker.Stop()

// 	var last time.Time

// 	fmt.Println("Starting... Press Ctrl+C to cancel or wait for timeout.")

//		for {
//			select {
//			case <-ctx.Done():
//				fmt.Println("Context canceled.")
//				extract(last)
//				return
//			case <-ctxTimeout.Done():
//				fmt.Println("Timeout reached.")
//				extract(last)
//				return
//			case <-ticker.C:
//				next := time.Now()
//				fmt.Println("Ticker triggered.")
//				extract(last)
//				ticker.Reset(10 * time.Second)
//				last = next
//			}
//		}
//	}
// package main

// import (
// 	"bufio"
// 	"fmt"
// 	"os"
// 	"sort"
// 	"strings"
// )

// // Hàm đọc tệp và trả về một map với các dòng duy nhất
// func readFileToSet(filename string) (map[string]struct{}, error) {
// 	file, err := os.Open(filename)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer file.Close()

// 	set := make(map[string]struct{})
// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		set[line] = struct{}{}
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return nil, err
// 	}

// 	return set, nil
// }
// func readFileToSet1(filename string) (map[string]struct{}, error) {
// 	file, err := os.Open(filename)
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer file.Close()

// 	set := make(map[string]struct{})
// 	scanner := bufio.NewScanner(file)
// 	for scanner.Scan() {
// 		line := scanner.Text()
// 		// Tìm vị trí của ký tự 'a'
// 		start := strings.Index(line, "http")

// 		// Kiểm tra nếu tìm thấy 'a'
// 		// Lấy chuỗi từ vị trí 'a' đến hết
// 		result := line[start:]
// 		result1 := result[:len(result)-2]

// 		set[result1] = struct{}{}
// 	}

// 	if err := scanner.Err(); err != nil {
// 		return nil, err
// 	}

// 	return set, nil
// }

// // Hàm so sánh 2 tệp và in ra các dòng chỉ có trong tệp 1
// func compareFiles(file1, file2 string) error {
// 	set1, err := readFileToSet(file1)
// 	if err != nil {
// 		return err
// 	}

// 	set2, err := readFileToSet1(file2)
// 	if err != nil {
// 		return err
// 	}
// 	count := 0
// 	// In ra những dòng có trong file1 nhưng không có trong file2
// 	var diff []string
// 	for line := range set1 {
// 		if _, found := set2[line]; !found {
// 			diff = append(diff, line)
// 			count++
// 		}
// 	}

// 	sort.Strings(diff) // Sắp xếp kết quả
// 	for _, line := range diff {
// 		fmt.Println(line)
// 	}
// 	fmt.Println(count)
// 	return nil
// }

// func main() {
// 	file1 := "test.txt"  // Tên file 1
// 	file2 := "test1.txt" // Tên file 2

// 	if err := compareFiles(file1, file2); err != nil { //chỉ có trong file 1
// 		fmt.Println("Error:", err)
// 	}
// }

// package main

// import (
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log"
// 	"os"
// 	"sync"
// )

// func main() {
// 	// Đường dẫn đến file JSON
// 	filePath := "D:\\OneDrive - zb87w\\STUDY\\Tuhoc\\Go\\FuffDirAndFile.json"

// 	// Đọc file JSON
// 	file, err := os.Open(filePath)
// 	if err != nil {
// 		log.Fatalf("Error opening file: %v", err)
// 	}
// 	defer file.Close()

// 	// Đọc toàn bộ nội dung của file
// 	byteValue, err := io.ReadAll(file)
// 	if err != nil {
// 		log.Fatalf("Error reading file: %v", err)
// 	}

// 	// Parse nội dung file JSON thành map
// 	var data map[string]interface{}
// 	err = json.Unmarshal(byteValue, &data)
// 	if err != nil {
// 		log.Fatalf("Error parsing JSON: %v", err)
// 	}

// 	// Lấy phần "results" từ JSON
// 	results, ok := data["results"].([]interface{})
// 	if !ok {
// 		log.Fatalf("Error: 'results' is not a valid array")
// 	}
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
// 	var wg sync.WaitGroup
// 	outputs := make(chan string, 50)
// 	wg.Add(1)
// 	go writeFiles(ctx, &wg, outputs, "dir")
// 	// Duyệt qua các phần tử trong "results" và chỉ in ra trường "FUZZ"
// 	wg.Add(1)
// 	go func() {
// 		for _, result := range results {
// 			item := result.(map[string]interface{})
// 			if input, found := item["input"].(map[string]interface{}); found {
// 				if fuzz, found := input["FUZZ"]; found {
// 					// fmt.Println(fuzz)
// 					outputs <- fuzz.(string) + "\n"
// 				}
// 			}
// 		}
// 		defer close(outputs)

// 		}()
// 		wg.Wait()
// 	}
// package main

// import (
// 	"bytes"
// 	"compress/flate"
// 	"compress/gzip"
// 	"fmt"
// 	"io"
// 	"net/http"
// 	"strconv"
// 	"time"

// 	"github.com/andybalholm/brotli"
// )

// const MAX_DOWNLOAD_SIZE = 5242880

// func GetContentLength(method, url string, headers map[string]string, body io.Reader, ignoreBody bool) (int64, error) {
// 	req, err := http.NewRequest(method, url, body)
// 	if err != nil {
// 		return 0, fmt.Errorf("Error creating request: %w", err)
// 	}

// 	for k, v := range headers {
// 		req.Header.Set(k, v)
// 	}

// 	client := &http.Client{
// 		Timeout: 10 * time.Second, // Thay đổi timeout nếu cần
// 	}

// 	resp, err := client.Do(req)
// 	if err != nil {
// 		return 0, fmt.Errorf("Error sending request: %w", err)
// 	}
// 	defer resp.Body.Close()

// 	// In thông tin debug về headers và kích thước từ header nếu có
// 	fmt.Println("Response Headers:", resp.Header)
// 	if sizeStr := resp.Header.Get("Content-Length"); sizeStr != "" {
// 		fmt.Printf("Content-Length from header: %s\n", sizeStr)
// 	}

// 	// Nếu ignoreBody là true, trả về Content-Length từ header nếu có
// 	if ignoreBody {
// 		if sizeStr := resp.Header.Get("Content-Length"); sizeStr != "" {
// 			size, err := strconv.Atoi(sizeStr)
// 			if err == nil {
// 				return int64(size), nil
// 			}
// 		}
// 		return 0, nil
// 	}

// 	// Xử lý nén nội dung nếu cần
// 	var bodyReader io.ReadCloser
// 	switch resp.Header.Get("Content-Encoding") {
// 	case "gzip":
// 		bodyReader, err = gzip.NewReader(resp.Body)
// 		if err != nil {
// 			return 0, fmt.Errorf("Error creating gzip reader: %w", err)
// 		}
// 	case "br":
// 		bodyReader = io.NopCloser(brotli.NewReader(resp.Body))
// 	case "deflate":
// 		bodyReader = flate.NewReader(resp.Body)
// 	default:
// 		bodyReader = resp.Body
// 	}

// 	// Đọc toàn bộ body để tính toán kích thước
// 	bodyBytes, err := io.ReadAll(bodyReader)
// 	if err != nil {
// 		return 0, fmt.Errorf("Error reading response body: %w", err)
// 	}

// 	fmt.Printf("Content-Length from body read: %d\n", len(bodyBytes))
// 	return int64(len(bodyBytes)), nil
// }

// func main() {
// 	// Ví dụ sử dụng hàm GetContentLength
// 	headers := map[string]string{
// 		"User-Agent": "Custom User Agent",
// 	}

// 	// Cấu hình ignoreBody dựa trên file cấu hình
// 	ignoreBody := false // Thay đổi theo cấu hình `ignorebody` từ file cấu hình

// 	// URL và dữ liệu yêu cầu
// 	method := "GET"
// 	url := "http://hackerone.com/" // Thay đổi URL thành URL đúng
// 	body := bytes.NewReader(nil)   // Không có body trong yêu cầu GET

//		contentLength, err := GetContentLength(method, url, headers, body, ignoreBody)
//		if err != nil {
//			fmt.Println("Error:", err)
//		} else {
//			fmt.Printf("Content-Length: %d\n", contentLength)
//		}
//	}
// package main

// import (
// 	"fmt"
// )

//	func main() {
//		a := "abcdeg"
//		fmt.Println(a[1 : len(a)-1]) // Output: "bcdeg"
//	}
// package main

// import (
// 	"bufio"
// 	"bytes"
// 	"context"
// 	"encoding/json"
// 	"fmt"
// 	"log"
// 	"net/http"
// 	"os"
// 	"sync"
// 	"time"

// 	"github.com/projectdiscovery/goflags"
// 	"github.com/projectdiscovery/gologger"
// 	"github.com/projectdiscovery/gologger/levels"
// 	"github.com/projectdiscovery/httpx/runner"
// )

// func writeFiles(ctx context.Context, wg *sync.WaitGroup, results <-chan string, ouputFile string) {
// 	defer wg.Done()
// 	// Mở file để ghi kết quả
// 	file, err := os.OpenFile(ouputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		fmt.Println("Error opening output file:", err)
// 		return
// 	}
// 	defer file.Close()

// 	for {
// 		select {
// 		case <-ctx.Done(): // Nếu nhận được tín hiệu hủy từ context
// 			fmt.Println("Context cancelled, stopping file write.")
// 			return
// 		case result, ok := <-results:
// 			if !ok {
// 				fmt.Println("hết write")
// 				return
// 			}
// 			//time.Sleep(1 * time.Second)
// 			_, err := file.Write([]byte(result + "\n"))
// 			fmt.Println("write", result)
// 			if err != nil {
// 				fmt.Println("Error writing to file:", err)
// 			}
// 		}
// 	}
// }
// func readFiles(ctx context.Context, wg *sync.WaitGroup, wordlist string, semaphore chan<- string) {
// 	defer wg.Done()

// 	file, err := os.Open(wordlist)
// 	if err != nil {
// 		fmt.Println("Error opening file:", err)
// 		close(semaphore)
// 		return
// 	}
// 	defer file.Close()

// 	scanner := bufio.NewScanner(file)
// 	for {
// 		select {
// 		case <-ctx.Done():
// 			// Nếu nhận tín hiệu hủy từ context, đóng semaphore và thoát
// 			fmt.Println("Context cancelled, stopping file read.")
// 			close(semaphore)
// 			return
// 		default:
// 			if !scanner.Scan() {
// 				// Đọc xong file hoặc gặp lỗi
// 				if err := scanner.Err(); err != nil {
// 					fmt.Println("Error reading file:", err)
// 				}
// 				close(semaphore)
// 				return
// 			}
// 			domain := scanner.Text()
// 			semaphore <- domain // Gửi domain vào channel semaphore để kiểm tra
// 		}
// 	}
// }
// func Httpx(wg *sync.WaitGroup, outChans chan string, urls []string) {
// 	//gologger.DefaultLogger.SetMaxLevel(levels.LevelVerbose) // increase the verbosity (optional)
// 	gologger.DefaultLogger.SetMaxLevel(levels.LevelSilent)

// 	apiEndpoint := "127.0.0.1:31234"

// 	options := runner.Options{
// 		Methods:         "GET",
// 		InputTargetHost: goflags.StringSlice(urls),
// 		Threads:         1,
// 		Silent:          true,
// 		TechDetect:      true,
// 		Output:          "linh.txt",
// 		HttpApiEndpoint: apiEndpoint,

// 		OnResult: func(r runner.Result) {
// 			// handle error
// 			if r.Err != nil {
// 				fmt.Printf("[Err] %s: %s\n", r.Input, r.Err)
// 				return
// 			}

// 			fmt.Printf("%s * %d * %s *%v*%v*%v\n", r.Input, r.StatusCode, r.Title, r.URL, r.Technologies, r.TechnologyDetails)
// 			outChans <- r.Input

// 		},
// 	}

// 	// after 3 seconds increase the speed to 50
// 	time.AfterFunc(3*time.Second, func() {
// 		client := &http.Client{}

// 		concurrencySettings := runner.Concurrency{Threads: 50}
// 		requestBody, err := json.Marshal(concurrencySettings)
// 		if err != nil {
// 			log.Fatalf("Error creating request body: %v", err)
// 		}

// 		req, err := http.NewRequest("PUT", fmt.Sprintf("http://%s/api/concurrency", apiEndpoint), bytes.NewBuffer(requestBody))
// 		if err != nil {
// 			log.Fatalf("Error creating PUT request: %v", err)
// 		}
// 		req.Header.Set("Content-Type", "application/json")

// 		resp, err := client.Do(req)
// 		if err != nil {
// 			log.Fatalf("Error sending PUT request: %v", err)
// 		}
// 		defer resp.Body.Close()

// 		if resp.StatusCode != http.StatusOK {
// 			log.Printf("Failed to update threads, status code: %d", resp.StatusCode)
// 		} else {
// 			log.Println("Threads updated to 50 successfully")
// 		}
// 	})

// 	if err := options.ValidateOptions(); err != nil {
// 		log.Fatal(err)
// 	}

// 	httpxRunner, err := runner.New(&options)
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	defer httpxRunner.Close()

// 	httpxRunner.RunEnumeration()
// 	close(outChans)
// 	wg.Done()
// }
// func HTTP(ctx context.Context) {
// 	var wg sync.WaitGroup
// 	outputChan := make(chan string, 50)
// 	inputChan := make(chan string, 50)
// 	// gologger.Silent()
// 	wg.Add(1)
// 	go readFiles(ctx, &wg, "D:\\OneDrive - zb87w\\STUDY\\Tuhoc\\Go\\test.txt", outputChan)
// 	wg.Add(1)
// 	go writeFiles(ctx, &wg, inputChan, "linh1.txt")

// 	// generate urls
// 	var urls []string
// 	for url := range outputChan {
// 		urls = append(urls, url)

// 	}
// 	wg.Add(1)
// 	go Httpx(&wg, inputChan, urls)
// 	wg.Wait()
// }
// func main() {
// 	ctx, cancel := context.WithCancel(context.Background())
// 	defer cancel()
// 	HTTP(ctx)

// }
// package main

// import (
// 	"fmt"
// 	"io"
// 	"log"
// 	"net"
// 	"net/http"
// 	"time"

// 	"github.com/PuerkitoBio/goquery"
// 	"github.com/miekg/dns"
// 	wappalyzer "github.com/projectdiscovery/wappalyzergo"
// )

// // Info chứa thông tin về HTTP/HTTPS
// type Info struct {
// 	URL        string
// 	StatusCode int
// 	Title      string
// }

// // DomainInfo chứa thông tin về domain
// type DomainInfo struct {
// 	DomainName     string
// 	Ips            []string
// 	PortAndService map[string]string
// 	HttpOrHttps    map[string]InfoWeb
// 	CName          []string
// }

// // InfoWeb chứa thông tin về công nghệ web
// type InfoWeb struct {
// 	TechnologyDetails map[string]wappalyzer.AppInfo
// 	Link              []string
// 	DirAndFile        []string
// 	FireWall          string
// 	Status            string
// 	Title             string
// }

// // CheckHTTPAndHTTPS kiểm tra HTTP và HTTPS của một domain
// func CheckHTTPAndHTTPS(domain string) (Info, Info, error) {
// 	var httpInfo, httpsInfo Info

// 	// Kiểm tra HTTP
// 	httpURL := "http://" + domain
// 	httpResp, err := http.Get(httpURL)
// 	if err != nil {
// 		return httpInfo, httpsInfo, fmt.Errorf("error checking HTTP: %v", err)
// 	}
// 	defer httpResp.Body.Close()

// 	httpInfo.URL = httpURL
// 	httpInfo.StatusCode = httpResp.StatusCode
// 	httpInfo.Title = extractTitle(httpResp)

// 	// Kiểm tra HTTPS
// 	httpsURL := "https://" + domain
// 	httpsResp, err := http.Get(httpsURL)
// 	if err != nil {
// 		return httpInfo, httpsInfo, fmt.Errorf("error checking HTTPS: %v", err)
// 	}
// 	defer httpsResp.Body.Close()

// 	httpsInfo.URL = httpsURL
// 	httpsInfo.StatusCode = httpsResp.StatusCode
// 	httpsInfo.Title = extractTitle(httpsResp)

// 	return httpInfo, httpsInfo, nil
// }

// // extractTitle lấy title từ phản hồi
// func extractTitle(resp *http.Response) string {
// 	doc, err := goquery.NewDocumentFromReader(resp.Body)
// 	if err != nil {
// 		return "Error parsing document"
// 	}

// 	// Lấy title từ thẻ <title>
// 	title := doc.Find("title").Text()
// 	return title
// }

// // GetDomainInfo thu thập thông tin về domain
// func GetDomainInfo(domain string) {
// 	httpInfo, httpsInfo, err := CheckHTTPAndHTTPS(domain)
// 	if err != nil {
// 		fmt.Println("Error:", err)
// 		return
// 	}

// 	// Lấy IP của domain
// 	ips, err := net.LookupIP(domain)
// 	if err != nil {
// 		log.Fatal("Error getting IP:", err)
// 	}

// 	// Chuyển đổi []net.IP thành []string
// 	var ipStrings []string
// 	for _, ip := range ips {
// 		ipStrings = append(ipStrings, ip.String())
// 	}

// 	// Khởi tạo DomainInfo
// 	domainInfo := DomainInfo{
// 		DomainName:  domain,
// 		Ips:         ipStrings,
// 		HttpOrHttps: make(map[string]InfoWeb),
// 		CName:       []string{},
// 	}

// 	// Thêm thông tin HTTP vào DomainInfo
// 	domainInfo.HttpOrHttps[httpInfo.URL] = InfoWeb{
// 		TechnologyDetails: make(map[string]wappalyzer.AppInfo),
// 		Title:             httpInfo.Title,
// 		Status:            fmt.Sprintf("%d", httpInfo.StatusCode),
// 	}

// 	// Thêm thông tin HTTPS vào DomainInfo
// 	domainInfo.HttpOrHttps[httpsInfo.URL] = InfoWeb{
// 		TechnologyDetails: make(map[string]wappalyzer.AppInfo),
// 		Title:             httpsInfo.Title,
// 		Status:            fmt.Sprintf("%d", httpsInfo.StatusCode),
// 	}

// 	// Thu thập công nghệ sử dụng Wappalyzer
// 	collectTechnology(domain, httpInfo.URL)
// 	collectTechnology(domain, httpsInfo.URL)

// 	// In kết quả
// 	fmt.Printf("%s [%s]\n", domain, httpInfo.Title)
// 	fmt.Printf("%+v\n", domainInfo)
// }

// // collectTechnology thu thập thông tin công nghệ của domain
// func collectTechnology(domain, url string) {
// 	resp, err := http.Get(url)
// 	if err != nil {
// 		log.Fatal("Error getting technology info:", err)
// 	}
// 	defer resp.Body.Close()

// 	data, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		log.Fatal("Error reading response body:", err)
// 	}

// 	wappalyzerClient, err := wappalyzer.New()
// 	if err != nil {
// 		log.Fatal("Error creating Wappalyzer client:", err)
// 	}

// 	// Thu thập fingerprints và fingerprints với categories
// 	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
// 	fingerprintsWithCats := wappalyzerClient.FingerprintWithInfo(resp.Header, data)

// 	// In ra kết quả
// 	fmt.Printf("Fingerprints: %v\n", fingerprints)
// 	fmt.Printf("Fingerprints with categories: %v\n", fingerprintsWithCats)

// 	// Nếu muốn in theo cách bạn đã đề cập
// 	for tech, info := range fingerprints {
// 		fmt.Printf("%s: %+v\n", tech, info)
// 	}
// }

// func Dig(domain string, qtype uint16) []dns.RR {
// 	// Tạo DNS message
// 	msg := new(dns.Msg)
// 	msg.SetQuestion(dns.Fqdn(domain), qtype)
// 	msg.RecursionDesired = true

// 	// Chọn DNS server để truy vấn
// 	dnsServer := "8.8.8.8:53" // Google DNS

// 	// Tạo client để gửi yêu cầu DNS
// 	client := new(dns.Client)
// 	client.Timeout = 5 * time.Second

// 	// Gửi yêu cầu DNS
// 	response, _, err := client.Exchange(msg, dnsServer)
// 	if err != nil {
// 		fmt.Printf("Error querying %s for type %d: %v\n", domain, qtype, err)
// 		return []dns.RR{}
// 	}

// 	// Kiểm tra nếu không có bản ghi trả về
// 	if len(response.Answer) == 0 {
// 		fmt.Printf("No records found for %s (type %d)\n", domain, qtype)
// 		return []dns.RR{}
// 	}

// 	// In kết quả trả về
// 	for _, ans := range response.Answer {
// 		fmt.Println(ans.(*dns.SOA).Expire, "*", ans.(*dns.SOA).Ns, "*", ans.(*dns.SOA).Refresh, "*", ans.(*dns.SOA).Mbox, "*", ans.(*dns.SOA).Hdr)
// 	}

// 	return response.Answer
// }

// func main() {
// 	domain := "hackerone.com"
// 	// fmt.Println("A records:")
// 	// Dig(domain, dns.TypeA)

// 	// fmt.Println("AAAA records:")
// 	// Dig(domain, dns.TypeAAAA)

// 	// fmt.Println("CNAME records:")
// 	// Dig(domain, dns.TypeCNAME)

// 	// fmt.Println("HTTPS records:")
// 	// Dig(domain, dns.TypeHTTPS)

// 	fmt.Println("SOA records:")
// 	Dig(domain, dns.TypeSOA)

// 	// fmt.Println("TXT records:")
// 	// Dig(domain, dns.TypeTXT)

// 	// fmt.Println("MX records:")
// 	// Dig(domain, dns.TypeMX)

// 	// fmt.Println("NS records:")
// 	// Dig(domain, dns.TypeNS)
// 	// domain := "google.com"

//		// // Truy vấn TXT record
//		// txtRecords, err := net.Lookup(domain)
//		// if err != nil {
//		// 	fmt.Printf("Error looking up TXT records for %s: %v\n", domain, err)
//		// } else {
//		// 	fmt.Println("TXT records:", txtRecords)
//		// }
//	}
// package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"net/http"
// 	"strings"
// )

// // Cấu trúc để lưu thông tin IP từ ipinfo.io
// type IPInfo struct {
// 	IP       string `json:"ip"`
// 	Hostname string `json:"hostname"`
// 	Org      string `json:"org"`
// }

// // Hàm kiểm tra tên miền có chứa dấu hiệu của proxy/VPN
// func containsProxyOrVpn(domain string) bool {
// 	proxyKeywords := []string{"proxy", "vpn", "tor", "anon", "cloudflare", "akamai", "fastly", "cloudfront", "cdn"}

// 	for _, keyword := range proxyKeywords {
// 		if strings.Contains(strings.ToLower(domain), keyword) {
// 			return true
// 		}
// 	}
// 	return false
// }

// // Hàm gọi API ipinfo.io để lấy thông tin chi tiết về IP
// func getIPInfo(ip string) {
// 	resp, err := http.Get("https://ipinfo.io/" + ip + "/json")
// 	if err != nil {
// 		fmt.Println(ip, "không phải là IP trung gian.")
// 	}
// 	defer resp.Body.Close()

// 	var info IPInfo
// 	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
// 		fmt.Println(ip, "không phải là IP trung gian.")
// 	}
// 	fmt.Println(info.Org)
// 	// Kiểm tra thông tin tổ chức
// 	if info.Org != "" {
// 		if containsProxyOrVpn(info.Org) {
// 			fmt.Println(ip, "là IP trung gian (proxy/VPN).")
// 		} else {
// 			fmt.Println(ip, "không phải là IP trung gian.")
// 		}
// 	}

// }

// func main() {
// 	ip := "52.60.165.183" // IP ví dụ

// 	getIPInfo(ip)

// }
// package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"net"
// 	"net/http"
// 	"strings"
// )

// // Fastly IP list structure
// type GcoreIPs struct {
// 	Addresses []string `json:"addresses"`
// }

// // Fastly IP list structure
// type FastlyIPs struct {
// 	Addresses []string `json:"addresses"`
// }

// // Fastly IP list structure
// type IncapsulaIPs struct {
// 	IpRanges []string `json:"ipRanges"`
// }

// // Cloudflare IP list structure
// type CloudflareIPs struct {
// 	Addresses []string `json:"addresses"`
// }

// type AWSIPRanges struct {
// 	Prefixes []struct {
// 		IPPrefix string `json:"ip_prefix"`
// 		Service  string `json:"service"`
// 	} `json:"prefixes"`
// }

// func getFastlyIPs() ([]string, error) {
// 	resp, err := http.Get("https://api.fastly.com/public-ip-list")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	var fastly FastlyIPs
// 	if err := json.NewDecoder(resp.Body).Decode(&fastly); err != nil {
// 		return nil, err
// 	}

// 	return fastly.Addresses, nil
// }

// func getIncapsulaIPs() ([]string, error) {
// 	resp, err := http.Get("https://my.imperva.com/api/integration/v1/ips")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	var incapsula IncapsulaIPs
// 	if err := json.NewDecoder(resp.Body).Decode(&incapsula); err != nil {
// 		return nil, err
// 	}

// 	return incapsula.IpRanges, nil
// }

// func getGcoreIPs() ([]string, error) {
// 	resp, err := http.Get("https://api.gcore.com/cdn/public-ip-list")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	var gcore GcoreIPs
// 	if err := json.NewDecoder(resp.Body).Decode(&gcore); err != nil {
// 		return nil, err
// 	}

// 	return gcore.Addresses, nil
// }

// func getCloudflareIPs() ([]string, error) {
// 	resp, err := http.Get("https://www.cloudflare.com/ips-v4")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()
// 	body, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		return nil, err
// 	}
// 	cloudflare := strings.Split(string(body), "\n")
// 	return cloudflare, nil
// }

// func getAWSIPs() ([]string, error) {
// 	resp, err := http.Get("https://ip-ranges.amazonaws.com/ip-ranges.json")
// 	if err != nil {
// 		return nil, err
// 	}
// 	defer resp.Body.Close()

// 	var aws AWSIPRanges
// 	if err := json.NewDecoder(resp.Body).Decode(&aws); err != nil {
// 		return nil, err
// 	}

// 	var ipPrefixes []string
// 	for _, prefix := range aws.Prefixes {
// 		if strings.Contains(strings.ToLower(prefix.Service), "cloudfront") {
// 			ipPrefixes = append(ipPrefixes, prefix.IPPrefix)
// 		}
// 	}
// 	return ipPrefixes, nil
// }

// func isIPInRange(ip string, ranges []string) bool {
// 	ipAddr := net.ParseIP(ip)
// 	if ipAddr == nil {
// 		fmt.Printf("Invalid IP address: %s\n", ip)
// 		return false
// 	}

// 	for _, r := range ranges {
// 		_, netRange, err := net.ParseCIDR(r)
// 		if err != nil {
// 			fmt.Printf("Error parsing CIDR: %s\n", r)
// 			continue // Bỏ qua dải IP không hợp lệ
// 		}
// 		if netRange.Contains(ipAddr) {
// 			return true
// 		}
// 	}
// 	return false
// }

// func main() {
// 	fastlyIPs, err := getFastlyIPs()
// 	if err != nil {
// 		fmt.Println("Error getting Fastly IPs:", err)
// 		return
// 	}
// 	fmt.Println(fastlyIPs)
// 	gcoreIPs, err := getGcoreIPs()
// 	if err != nil {
// 		fmt.Println("Error getting gcore IPs:", err)
// 		return
// 	}
// 	fmt.Println(gcoreIPs)

// 	cloudflareIPs, err := getCloudflareIPs()
// 	if err != nil {
// 		fmt.Println("Error getting Cloudflare IPs:", err)
// 		return
// 	}
// 	fmt.Println(cloudflareIPs)

// 	incapsulaIPs, err := getIncapsulaIPs()
// 	if err != nil {
// 		fmt.Println("Error getting Cloudflare IPs:", err)
// 		return
// 	}
// 	fmt.Println(incapsulaIPs)

// 	awsIPs, err := getAWSIPs()
// 	if err != nil {
// 		fmt.Println("Error getting AWS IPs:", err)
// 		return
// 	}
// 	fmt.Println(awsIPs)
// 	// allIPs := append(fastlyIPs, awsIPs...)
// 	// allIPs = append(allIPs, cloudflareIPs...)

// 	ipToCheck := "185.199.108.153" // Thay thế bằng IP bạn muốn kiểm tra
// 	if isIPInRange(ipToCheck, fastlyIPs) {
// 		fmt.Printf("%s is in the intermediary fastlyIPs ranges.\n", ipToCheck)
// 	} else if isIPInRange(ipToCheck, cloudflareIPs) {
// 		fmt.Printf("%s is in the intermediary cloudflareIPs ranges.\n", ipToCheck)
// 	} else if isIPInRange(ipToCheck, awsIPs) {
// 		fmt.Printf("%s is in the intermediary awsCloudFrontIPs ranges.\n", ipToCheck)
// 	} else {
// 		fmt.Printf("%s is not in the intermediary Ip ranges.\n", ipToCheck)
// 	}
// }

// package main

// import (
// 	"encoding/xml"
// 	"fmt"
// 	"io"
// 	"os"
// 	"path/filepath"
// 	"strings"
// )

// func ReadFilesSimple(file string) string {
// 	// Mở file để đọc
// 	inputFile, err := os.Open(file)
// 	if err != nil {
// 		fmt.Println("Error opening file:", err)
// 		return ""
// 	}
// 	defer inputFile.Close()

// 	// Đọc toàn bộ nội dung file vào biến
// 	content, err := io.ReadAll(inputFile)
// 	if err != nil {
// 		fmt.Println("Error reading file:", err)
// 		return ""
// 	}
// 	return string(content)
// }
// func Getwd() string {
// 	cwd, err := os.Getwd()
// 	if err != nil {
// 		fmt.Println("Error getting current working directory:", err)
// 		return ""
// 	}
// 	return filepath.ToSlash(cwd)
// }

// type OsMatch struct {
// 	Name     string `xml:"name,attr"`
// 	Accuracy string `xml:"accuracy,attr"`
// }
// type OsClass struct {
// 	Type string `xml:"type,attr"`
// }
// type Port struct {
// 	Protocol string  `xml:"protocol,attr"`
// 	PortID   string  `xml:"portid,attr"`
// 	State    State   `xml:"state"`
// 	Service  Service `xml:"service"`
// }

// type State struct {
// 	State string `xml:"state,attr"`
// }

// type Service struct {
// 	Name    string `xml:"name,attr"`
// 	Tunnel  string `xml:"tunnel,attr"`
// 	Product string `xml:"product,attr"`
// 	Version string `xml:"version,attr"`
// }

// func main() {
// 	// ctx, cancel := context.WithCancel(context.Background())
// 	// defer cancel()
// 	// //workDirectory := Getwd()
// 	// var scanPortAndService string
// 	// var ports []*port.Port
// 	// options := runner.Options{
// 	// 	Host:     goflags.StringSlice{"hackerone.com"},
// 	// 	ScanType: "s",
// 	// 	TopPorts: "1000",
// 	// 	Nmap:     true,
// 	// 	NmapCLI:  "nmap -O -sV",
// 	// 	Silent:   true,
// 	// 	OnResult: func(hr *result.HostResult) {
// 	// 		// fmt.Println(hr.Host, hr.Ports)
// 	// 		ports = hr.Ports
// 	// 	},
// 	// }
// 	// fmt.Println(ports)
// 	// naabuRunner, err := runner.NewRunner(&options)
// 	// if err != nil {
// 	// 	log.Fatal(err)
// 	// }
// 	// defer naabuRunner.Close()

// 	// naabuRunner.RunEnumeration(ctx, &scanPortAndService)
// 	// fmt.Println(numberhPort)
// 	output := ReadFilesSimple("C:\\Users\\minhl\\recon\\src\\linh4.txt")
// 	instances := strings.TrimSpace(output)

// 	if instances != "" {
// 		//Get os
// 		flagCopyPort := false
// 		for _, instance := range strings.Split(instances, "\r\n") {
// 			instance = strings.TrimSpace(instance)
// 			if strings.Contains(instance, "<port protocol") {
// 				// fmt.Println("*", instance, "*")
// 				var port Port
// 				err := xml.Unmarshal([]byte(instance), &port)
// 				if err != nil {
// 					fmt.Println("Error:", err)
// 					return
// 				}
// 				service := ""
// 				if port.Service.Tunnel != "" {
// 					service = port.Service.Tunnel + "/" + port.Service.Name
// 				} else {
// 					service = port.Service.Name
// 				}
// 				fmt.Println("Port:", port.PortID+"/"+port.Protocol, "State:", port.State.State, "Service:", service, "Version:", port.Service.Product+" "+port.Service.Version)
// 			}
// 			var osMatch OsMatch
// 			if strings.Contains(instance, "<osmatch") {
// 				instance = instance + "</osmatch>"

// 				// Giải mã XML
// 				err := xml.Unmarshal([]byte(instance), &osMatch)
// 				if err != nil {
// 					fmt.Println("Lỗi khi giải mã XML:", err)
// 					return
// 				}
// 				fmt.Println("Name:", osMatch.Name+" ("+osMatch.Accuracy+")")
// 				flagCopyPort = true
// 			}
// 			if strings.Contains(instance, "<osclass") && flagCopyPort {
// 				var osClass OsClass
// 				// Giải mã XML
// 				err := xml.Unmarshal([]byte(instance), &osClass)
// 				if err != nil {
// 					fmt.Println("Lỗi khi giải mã XML:", err)
// 					return
// 				}
// 				fmt.Println("Devicetype::", osClass.Type)
// 				flagCopyPort = false
// 			}

// 		}
// 	}
// }

// // package main

// // import (
// // 	"fmt"
// // 	"net"

// // 	"github.com/projectdiscovery/cdncheck"
// // )

// // func main() {
// // 	client := cdncheck.New()
// // 	ip := net.ParseIP("185.199.108.153")

// // 	// checks if an IP is contained in the cdn denylist
// // 	matched, val, err := client.CheckCDN(ip)
// // 	if err != nil {
// // 		panic(err)
// // 	}

// // 	if matched {
// // 		fmt.Printf("%v is a %v\n", ip, val)
// // 	} else {
// // 		fmt.Printf("%v is not a CDN\n", ip)
// // 	}

// // 	// checks if an IP is contained in the cloud denylist
// // 	matched, val, err = client.CheckCloud(ip)
// // 	if err != nil {
// // 		panic(err)
// // 	}

// // 	if matched {
// // 		fmt.Printf("%v is a %v\n", ip, val)
// // 	} else {
// // 		fmt.Printf("%v is not a Cloud\n", ip)
// // 	}

// // 	// checks if an IP is contained in the waf denylist
// // 	matched, val, err = client.CheckWAF(ip)
// // 	if err != nil {
// // 		panic(err)
// // 	}

// // 	if matched {
// // 		fmt.Printf("%v WAF is %v\n", ip, val)
// // 	} else {
// // 		fmt.Printf("%v is not a WAF\n", ip)
// // 	}
// // }
// package main

// import (
// 	"bufio"
// 	"encoding/json"
// 	"flag"
// 	"fmt"
// 	"io/ioutil"
// 	"net/http"
// 	"net/url"
// 	"os"
// 	"strings"
// 	"sync"
// 	"time"
// )

// func main() {

// 	var domains []string

// 	var dates bool
// 	flag.BoolVar(&dates, "dates", false, "show date of fetch in the first column")

// 	var noSubs bool
// 	flag.BoolVar(&noSubs, "no-subs", false, "don't include subdomains of the target domain")

// 	var getVersionsFlag bool
// 	flag.BoolVar(&getVersionsFlag, "get-versions", false, "list URLs for crawled versions of input URL(s)")

// 	flag.Parse()

// 	if flag.NArg() > 0 {
// 		// fetch for a single domain
// 		domains = []string{flag.Arg(0)}
// 	} else {

// 		// fetch for all domains from stdin
// 		sc := bufio.NewScanner(os.Stdin)
// 		for sc.Scan() {
// 			domains = append(domains, sc.Text())
// 		}

// 		if err := sc.Err(); err != nil {
// 			fmt.Fprintf(os.Stderr, "failed to read input: %s\n", err)
// 		}
// 	}

// 	// get-versions mode
// 	if getVersionsFlag {

// 		for _, u := range domains {
// 			versions, err := getVersions(u)
// 			if err != nil {
// 				continue
// 			}
// 			fmt.Println(strings.Join(versions, "\n"))
// 		}

// 		return
// 	}

// 	fetchFns := []fetchFn{
// 		getWaybackURLs,
// 		getCommonCrawlURLs,
// 		getVirusTotalURLs,
// 	}

// 	for _, domain := range domains {

// 		var wg sync.WaitGroup
// 		wurls := make(chan wurl)

// 		for _, fn := range fetchFns {
// 			wg.Add(1)
// 			fetch := fn
// 			go func() {
// 				defer wg.Done()
// 				resp, err := fetch(domain, noSubs)
// 				if err != nil {
// 					return
// 				}
// 				for _, r := range resp {
// 					if noSubs && isSubdomain(r.url, domain) {
// 						continue
// 					}
// 					wurls <- r
// 				}
// 			}()
// 		}

// 		go func() {
// 			wg.Wait()
// 			close(wurls)
// 		}()

// 		seen := make(map[string]bool)
// 		for w := range wurls {
// 			if _, ok := seen[w.url]; ok {
// 				continue
// 			}
// 			seen[w.url] = true

// 			if dates {

// 				d, err := time.Parse("20060102150405", w.date)
// 				if err != nil {
// 					fmt.Fprintf(os.Stderr, "failed to parse date [%s] for URL [%s]\n", w.date, w.url)
// 				}

// 				fmt.Printf("%s %s\n", d.Format(time.RFC3339), w.url)

// 			} else {
// 				fmt.Println(w.url)
// 			}
// 		}
// 	}

// }

// type wurl struct {
// 	date string
// 	url  string
// }

// type fetchFn func(string, bool) ([]wurl, error)

// func getWaybackURLs(domain string, noSubs bool) ([]wurl, error) {
// 	subsWildcard := "*."
// 	if noSubs {
// 		subsWildcard = ""
// 	}

// 	res, err := http.Get(
// 		fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=%s%s/*&output=json&collapse=urlkey", subsWildcard, domain),
// 	)
// 	if err != nil {
// 		fmt.Println("endgetWaybackURLs")
// 		return []wurl{}, err
// 	}

// 	raw, err := ioutil.ReadAll(res.Body)

// 	res.Body.Close()
// 	if err != nil {
// 		fmt.Println("end1getWaybackURLs")
// 		return []wurl{}, err
// 	}

// 	var wrapper [][]string
// 	err = json.Unmarshal(raw, &wrapper)

// 	out := make([]wurl, 0, len(wrapper))

// 	skip := true
// 	for _, urls := range wrapper {
// 		// The first item is always just the string "original",
// 		// so we should skip the first item
// 		if skip {
// 			skip = false
// 			continue
// 		}
// 		out = append(out, wurl{date: urls[1], url: urls[2]})
// 	}
// 	fmt.Println("getWaybackURLs", len(out))
// 	return out, nil

// }

// func getCommonCrawlURLs(domain string, noSubs bool) ([]wurl, error) {
// 	subsWildcard := "*."
// 	if noSubs {
// 		subsWildcard = ""
// 	}

// 	res, err := http.Get(
// 		fmt.Sprintf("http://index.commoncrawl.org/CC-MAIN-2018-22-index?url=%s%s/*&output=json", subsWildcard, domain),
// 	)
// 	if err != nil {
// 		fmt.Println("endgetCommonCrawlURLs")
// 		return []wurl{}, err
// 	}

// 	defer res.Body.Close()
// 	sc := bufio.NewScanner(res.Body)

// 	out := make([]wurl, 0)

// 	for sc.Scan() {

// 		wrapper := struct {
// 			URL       string `json:"url"`
// 			Timestamp string `json:"timestamp"`
// 		}{}
// 		err = json.Unmarshal([]byte(sc.Text()), &wrapper)

// 		if err != nil {
// 			continue
// 		}

// 		out = append(out, wurl{date: wrapper.Timestamp, url: wrapper.URL})
// 	}
// 	fmt.Println("getCommonCrawlURLs", len(out))
// 	return out, nil

// }

// func getVirusTotalURLs(domain string, noSubs bool) ([]wurl, error) {
// 	out := make([]wurl, 0)

// 	apiKey := os.Getenv("VT_API_KEY")
// 	if apiKey == "" {
// 		// no API key isn't an error,
// 		// just don't fetch
// 		fmt.Println("endgetVirusTotalURLs")
// 		return out, nil
// 	}

// 	fetchURL := fmt.Sprintf(
// 		"https://www.virustotal.com/vtapi/v2/domain/report?apikey=%s&domain=%s",
// 		apiKey,
// 		domain,
// 	)

// 	resp, err := http.Get(fetchURL)
// 	if err != nil {
// 		fmt.Println("endgetVirusTotalURLs1")
// 		return out, err
// 	}
// 	defer resp.Body.Close()

// 	wrapper := struct {
// 		URLs []struct {
// 			URL string `json:"url"`
// 			// TODO: handle VT date format (2018-03-26 09:22:43)
// 			//Date string `json:"scan_date"`
// 		} `json:"detected_urls"`
// 	}{}

// 	dec := json.NewDecoder(resp.Body)

// 	err = dec.Decode(&wrapper)

// 	for _, u := range wrapper.URLs {
// 		out = append(out, wurl{url: u.URL})
// 	}
// 	fmt.Println("getVirusTotalURLs", len(out))
// 	return out, nil

// }

// func isSubdomain(rawUrl, domain string) bool {
// 	u, err := url.Parse(rawUrl)
// 	if err != nil {
// 		// we can't parse the URL so just
// 		// err on the side of including it in output
// 		return false
// 	}

// 	return strings.ToLower(u.Hostname()) != strings.ToLower(domain)
// }

// func getVersions(u string) ([]string, error) {
// 	out := make([]string, 0)

// 	resp, err := http.Get(fmt.Sprintf(
// 		"http://web.archive.org/cdx/search/cdx?url=%s&output=json", u,
// 	))

// 	if err != nil {
// 		return out, err
// 	}
// 	defer resp.Body.Close()

// 	r := [][]string{}

// 	dec := json.NewDecoder(resp.Body)

// 	err = dec.Decode(&r)
// 	if err != nil {
// 		return out, err
// 	}

// 	first := true
// 	seen := make(map[string]bool)
// 	for _, s := range r {

// 		// skip the first element, it's the field names
// 		if first {
// 			first = false
// 			continue
// 		}

// 		// fields: "urlkey", "timestamp", "original", "mimetype", "statuscode", "digest", "length"
// 		if seen[s[5]] {
// 			continue
// 		}
// 		seen[s[5]] = true
// 		out = append(out, fmt.Sprintf("https://web.archive.org/web/%sif_/%s", s[1], s[2]))
// 	}

// 	return out, nil
// }

// package main

// import (
// 	"fmt"
// 	"os/exec"
// )

// func main() {
// 	// Domain mà bạn muốn kiểm tra
// 	domain := "https://dichvucong.gov.vn"

// 	// Tạo lệnh để chạy file Python
// 	cmd := exec.Command("python", "wafw00f_scan.py ", domain)

// 	// Chạy lệnh và lấy output
// 	output, err := cmd.CombinedOutput()
// 	if err != nil {
// 		fmt.Printf("Error running Python script: %v\n", err)
// 		return
// 	}

//		// In kết quả từ file Python
//		fmt.Printf("WAF detection result for %s:\n%s\n", domain, string(output))
//	}
// package main

// import (
// 	"context"

// 	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
// 	syncutil "github.com/projectdiscovery/utils/sync"
// )

// func main() {
// 	ctx := context.Background()
// 	// when running nuclei in parallel for first time it is a good practice to make sure
// 	// templates exists first
// 	tm := installer.TemplateManager{}
// 	if err := tm.FreshInstallIfNotExists(); err != nil {
// 		panic(err)
// 	}

// 	// create nuclei engine with options
// 	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx)
// 	if err != nil {
// 		panic(err)
// 	}
// 	// setup sizedWaitgroup to handle concurrency
// 	sg, err := syncutil.New(syncutil.WithSize(10))
// 	if err != nil {
// 		panic(err)
// 	}

// 	// scan 1 = run dns templates on scanme.sh
// 	sg.Add()
// 	go func() {
// 		defer sg.Done()
// 		err = ne.ExecuteNucleiWithOpts([]string{"scanme.sh"},
// 			nuclei.WithTemplateFilters(nuclei.TemplateFilters{ProtocolTypes: "dns"}),
// 			nuclei.WithHeaders([]string{"X-Bug-Bounty: pdteam"}),
// 			nuclei.EnablePassiveMode(),
// 		)
// 		if err != nil {
// 			panic(err)
// 		}
// 	}()

// 	// scan 2 = run templates with oast tags on honey.scanme.sh
// 	sg.Add()
// 	go func() {
// 		defer sg.Done()
// 		err = ne.ExecuteNucleiWithOpts([]string{"http://honey.scanme.sh"}, nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}))
// 		if err != nil {
// 			panic(err)
// 		}
// 	}()

// 	// wait for all scans to finish
// 	sg.Wait()
// 	defer ne.Close()

//		// Output:
//		// [dns-saas-service-detection] scanme.sh
//		// [nameserver-fingerprint] scanme.sh
//		// [dns-saas-service-detection] honey.scanme.sh
//	}
// package main

// import (
// 	"fmt"
// 	"sync"
// 	"time"
// )

// var contstt int

// func checkDomain() {
// 	for i := 1; i <= 10; i++ {
// 		// Sử dụng \r để đưa con trỏ về đầu dòng và ghi đè số mới
// 		fmt.Printf("\rStt: %d", i)
// 		time.Sleep(1 * time.Second) // Giả lập việc xử lý (1 giây)
// 	}
// 	fmt.Println() // Xuống dòng sau khi hoàn thành
// }

// func main() {
// 	var wg sync.WaitGroup
// 	wg.Add(1)

// 	go func() {
// 		defer wg.Done()
// 		checkDomain()
// 	}()

//		wg.Wait()
//	}
// package main

// import (
// 	"context"
// 	"log"
// 	"sync"

// 	"github.com/projectdiscovery/goflags"
// 	"github.com/projectdiscovery/naabu/v2/pkg/result"
// 	"github.com/projectdiscovery/naabu/v2/pkg/runner"
// )

// func main() {
// 	var wg sync.WaitGroup
// 	ctx, cancel := context.WithCancel(context.Background())
// 	linh := []string{"cms.gumac.vn", "hrv.gumac.vn", "missgu.gumac.vn", "online.gumac.vn", "crm.gumac.vn", "quanly2.gumac.vn", "cdn.gumac.vn", "bungnosinhnhat.gumac.vn", "www.gumac.vn", "quanly.gumac.vn"}
// 	defer cancel()
// 	for i := 0; i < 10; i++ {
// 		wg.Add(1)
// 		go func(domain string) {
// 			options := runner.Options{
// 				Host:     goflags.StringSlice{domain},
// 				ScanType: "s",
// 				TopPorts: "1000",
// 				Silent:   true,
// 				OnResult: func(hr *result.HostResult) {
// 					log.Println(hr.Host, hr.Ports)
// 				},
// 			}

// 			naabuRunner, err := runner.NewRunner(&options)
// 			if err != nil {
// 				log.Fatal(err)
// 			}
// 			defer naabuRunner.Close()

// 			naabuRunner.RunEnumeration(ctx)
// 			wg.Done()
// 		}(linh[i])
// 	}
// 	wg.Wait()

// }
// package main

// import (
// 	"fmt"
// 	"log"
// 	"time"

// 	"github.com/miekg/dns"
// )

// // List of DNS servers to test
// var dnsServers = []string{
// 	"8.8.8.8:53",        // Google DNS
// 	"8.8.4.4:53",        // Google DNS
// 	"1.1.1.1:53",        // Cloudflare DNS
// 	"9.9.9.9:53",        // Quad9 DNS
// 	"208.67.222.222:53", // OpenDNS
// }

// func main() {
// 	domain := "google.com" // Domain to query

// 	for _, server := range dnsServers {
// 		start := time.Now()
// 		response, err := queryDNS(server, domain)
// 		if err != nil {
// 			log.Printf("Error querying %s: %v\n", server, err)
// 			continue
// 		}
// 		duration := time.Since(start)
// 		fmt.Printf("Response from %s in %v: %d answers\n", server, duration, len(response))
// 	}
// }

// // queryDNS sends a DNS query to the specified server for the given domain
// func queryDNS(server, domain string) ([]dns.RR, error) {
// 	msg := new(dns.Msg)
// 	msg.SetQuestion(dns.Fqdn(domain), dns.TypeA) // Query for A records
// 	msg.RecursionDesired = true

// 	client := new(dns.Client)
// 	client.Timeout = 5 * time.Second

// 	response, _, err := client.Exchange(msg, server)
// 	if err != nil {
// 		return nil, err
// 	}

//		return response.Answer, nil
//	}
// package main

// import (
// 	"encoding/json"
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"
// 	"os"
// )

// // Cấu trúc dữ liệu InfoWeb, InfoSubDomain, InfoDomain giống với file JSON của bạn
// type InfoWeb struct {
// 	TechnologyDetails map[string]interface{} `json:"technologydetails"`
// 	FireWall          string                 `json:"firewall"`
// 	Status            string                 `json:"status"`
// 	Title             string                 `json:"title"`
// }

// type InfoSubDomain struct {
// 	NameSubDomain  string             `json:"namesubdomain"`
// 	Country        string             `json:"country"`
// 	Ips            []string           `json:"ips"`
// 	PortAndService map[string]string  `json:"portsandservice"`
// 	Os             []string           `json:"os"`
// 	HttpOrHttps    map[string]InfoWeb `json:"httporhttps"`
// 	CName          []string           `json:"cname"`
// }

// type InfoDomain struct {
// 	MXRecords  []string                 `json:"mxrecords"`
// 	NSRecords  []string                 `json:"nsrecords"`
// 	SOARecords []string                 `json:"soarecords"`
// 	TXTRecords []string                 `json:"txtrecords"`
// 	SubDomain  map[string]InfoSubDomain `json:"subdomain"`
// }

// var ListDomain map[string]InfoDomain

// // Hàm để đọc file JSON
// func loadJSONFile(fileName string) error {
// 	// Đọc file JSON
// 	jsonFile, err := os.Open(fileName)
// 	if err != nil {
// 		return fmt.Errorf("lỗi mở file: %v", err)
// 	}
// 	defer jsonFile.Close()

// 	// Đọc nội dung file
// 	byteValue, err := io.ReadAll(jsonFile)
// 	if err != nil {
// 		return fmt.Errorf("lỗi đọc file: %v", err)
// 	}

// 	// Giải mã dữ liệu JSON thành map
// 	err = json.Unmarshal(byteValue, &ListDomain)
// 	if err != nil {
// 		return fmt.Errorf("lỗi giải mã JSON: %v", err)
// 	}

// 	return nil
// }

// // Handler cho endpoint trả về dữ liệu JSON
// func jsonHandler(w http.ResponseWriter, r *http.Request) {
// 	// Thiết lập header cho response
// 	w.Header().Set("Content-Type", "application/json")

// 	// Chuyển dữ liệu ListDomain sang JSON
// 	jsonData, err := json.MarshalIndent(ListDomain, "", "  ")
// 	if err != nil {
// 		http.Error(w, "Không thể chuyển dữ liệu sang JSON", http.StatusInternalServerError)
// 		return
// 	}

// 	// Gửi dữ liệu JSON về client
// 	w.Write(jsonData)
// }

// func main() {
// 	// Đọc file JSON "linh.json"
// 	err := loadJSONFile("list_domain.json")
// 	if err != nil {
// 		log.Fatalf("Lỗi tải file JSON: %v", err)
// 	}

// 	// Khởi tạo HTTP server ở cổng 8080
// 	http.HandleFunc("/data", jsonHandler)

// 	fmt.Println("Server chạy tại http://localhost:8080/data")
// 	if err := http.ListenAndServe(":8080", nil); err != nil {
// 		log.Fatalf("Không thể khởi chạy server: %v", err)
// 	}
// }

// package main

// import (
// 	"fmt"
// 	"io"
// 	"net/http"
// )

// func LengthResponse(domain string, host string) (int, bool) {
// 	var flaghttp = false

// 	// Tạo yêu cầu cho HTTPS
// 	reqhttps, err := http.NewRequest("GET", "https://"+domain, nil)
// 	if err != nil {
// 		fmt.Println("Error creating request for HTTPS:", err)
// 		return 0, false
// 	}
// 	reqhttps.Host = host

// 	// Tạo yêu cầu cho HTTP
// 	reqhttp, err := http.NewRequest("GET", "http://"+domain, nil)
// 	if err != nil {
// 		fmt.Println("Error creating request for HTTP:", err)
// 		return 0, false
// 	}
// 	reqhttp.Host = host

// 	client := &http.Client{}

// 	// Gửi yêu cầu HTTPS
// 	resp, err := client.Do(reqhttps)
// 	if err == nil {
// 		defer resp.Body.Close()
// 		body, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			fmt.Println("Error reading HTTPS response body:", err)
// 			return 0, false
// 		}
// 		return len(body), false // Không cần gửi HTTP nếu HTTPS thành công
// 	} else {
// 		flaghttp = true // Đánh dấu cần gửi HTTP nếu HTTPS thất bại
// 	}

// 	// Gửi yêu cầu HTTP nếu HTTPS không thành công
// 	if flaghttp {
// 		resp, err = client.Do(reqhttp)
// 		if err != nil {
// 			fmt.Println("Error sending request for HTTP:", err)
// 			return 0, true
// 		}
// 		defer resp.Body.Close()

// 		body, err := io.ReadAll(resp.Body)
// 		if err != nil {
// 			fmt.Println("Error reading HTTP response body:", err)
// 			return 0, true
// 		}

// 		return len(body), true
// 	}

// 	return 0, false // Trả về 0 nếu cả hai yêu cầu đều không thành công
// }

// func main() {
// 	length, flag := LengthResponse("hackerone.com", "abcdef.hackerone.com")
// 	if flag {
// 		fmt.Println("HTTP request was used, response length:", length)
// 	} else {
// 		fmt.Println("HTTPS request was successful, response length:", length)
// 	}
// }

// package main

// import (
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"

// 	wappalyzer "github.com/projectdiscovery/wappalyzergo"
// )

// func main() {
// 	resp, err := http.DefaultClient.Get("https://www.hackerone.com")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	data, _ := io.ReadAll(resp.Body) // Ignoring error for example

// 	wappalyzerClient, err := wappalyzer.New()
// 	fingerprintsWithInfo := wappalyzerClient.FingerprintWithInfo(resp.Header, data)
// 	fmt.Printf("%v\n", fingerprintsWithInfo)

// 	// Output: map[Acquia Cloud Platform:{} Amazon EC2:{} Apache:{} Cloudflare:{} Drupal:{} PHP:{} Percona:{} React:{} Varnish:{}]
// }

// package main

// import (
// 	"fmt"
// 	"log"

// 	"github.com/likexian/whois"
// 	whoisparser "github.com/likexian/whois-parser"
// )

// func main() {
// 	ip := "dichvucong.gov.vn" // Địa chỉ IP hoặc tên miền cần tra cứu

// 	// Thực hiện tra cứu thông tin WHOIS
// 	result, err := whois.Whois(ip)
// 	if err != nil {
// 		log.Fatalf("Lỗi khi tra cứu WHOIS: %v", err)
// 	}

// 	// Phân tích kết quả WHOIS
// 	parsedResult, err := whoisparser.Parse(result)
// 	if err != nil {
// 		log.Fatalf("Lỗi khi phân tích kết quả WHOIS: %v", err)
// 	}

//		// Hiển thị các thông tin quan trọng
//		fmt.Printf("Domain: %s\n", parsedResult.Domain.Domain)
//		fmt.Printf("Registrar: %s\n", parsedResult.Registrar.Name)
//		fmt.Printf("Country: %s\n", parsedResult.Registrant.Country)
//		fmt.Printf("Creation Date: %s\n", parsedResult.Domain.CreatedDate)
//		fmt.Printf("Expiration Date: %s\n", parsedResult.Domain.ExpirationDate)
//	}
// package main

// import (
// 	"context"

// 	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
// )

//	func main() {
//		ne, err := nuclei.NewNucleiEngineCtx(context.Background(),
//			nuclei.WithTemplateFilters(nuclei.TemplateFilters{Tags: []string{"oast"}}),
//			nuclei.EnableStatsWithOpts(nuclei.StatsOptions{MetricServerPort: 6064}), // optionally enable metrics server for better observability
//		)
//		if err != nil {
//			panic(err)
//		}
//		// load targets and optionally probe non http/https targets
//		ne.LoadTargets([]string{"http://honey.scanme.sh"}, false)
//		err = ne.ExecuteWithCallback(nil)
//		if err != nil {
//			panic(err)
//		}
//		defer ne.Close()
//	}
// package main

// import (
// 	"fmt"
// 	"os"
// 	"time"

// 	"github.com/jedib0t/go-pretty/table"
// )

// type URLInfo struct {
// 	Loc        string
// 	StatusCode int
// 	LastMod    string
// 	Changefreq string
// 	Priority   string
// }

// func displaySitemap(urlsInfo []URLInfo) {
// 	t := table.NewWriter()
// 	t.SetOutputMirror(os.Stdout)
// 	t.AppendHeader(table.Row{"URL", "STATUS", "LAST MODIFIED", "CHANGEFREQ", "PRIORITY"})

// 	// Render bảng lần đầu
// 	//t.Render()

// 	// Thêm từng URL vào bảng theo thời gian thực
// 	for _, urlInfo := range urlsInfo {
// 		time.Sleep(1 * time.Second) // Giả lập thêm dữ liệu theo thời gian thực

// 		status := fmt.Sprintf("%d", urlInfo.StatusCode)
// 		if urlInfo.StatusCode == 0 {
// 			status = "N/A"
// 		}

// 		// Thêm hàng mới vào bảng
// 		t.AppendRows([]table.Row{
// 			{urlInfo.Loc, status, urlInfo.LastMod, urlInfo.Changefreq, urlInfo.Priority},
// 		})

// 		// Clear màn hình và render lại bảng
// 		fmt.Print("\033[H\033[J") // Clear màn hình
// 		t.Render()
// 	}

// 	// Đợi người dùng nhấn phím trước khi thoát
// 	fmt.Println("Press Enter to continue...")
// 	fmt.Scanln() // Đợi nhấn Enter
// }

// func main() {
// 	// Dữ liệu mẫu
// 	urls := []URLInfo{
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", "0.8"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.coqwem/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.cqweom/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.cowqem/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.comw/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.coms/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.cwqm/page2", 404, "2023-09-25", "weekly", "0.5"},
// 		{"h tXtps://example.com/page2", 404, "2023-09-25", "weekly", "0.5"},
// 	}

// 	displaySitemap(urls)
// }

// package main

// import (
// 	"fmt"
// 	"os"
// 	"time"

// 	"github.com/olekukonko/tablewriter"
// )

// type URLInfo struct {
// 	Loc        string
// 	StatusCode int
// 	LastMod    string
// 	Changefreq string
// 	Priority   string
// }

// type Analysis struct {
// 	TotalURLs  int
// 	UniqueURLs int
// 	BrokenURLs int
// }

// func moveCursorToStart() {
// 	// Di chuyển con trỏ về vị trí đầu tiên (1,1) bằng escape sequence
// 	fmt.Print("\033[H")
// }

// func clearScreen() {
// 	// Xóa toàn bộ màn hình
// 	fmt.Print("\033[2J")
// }

// func displaySitemap(urlsInfo []URLInfo, analysis Analysis) {
// 	// Tạo bảng mới và thêm header
// 	table := tablewriter.NewWriter(os.Stdout)
// 	table.SetHeader([]string{"URL", "Status", "Last Modified", "Changefreq", "Priority"})

// 	// Set styles
// 	table.SetHeaderColor(
// 		tablewriter.Colors{tablewriter.Bold, tablewriter.FgMagentaColor},
// 		tablewriter.Colors{tablewriter.FgCyanColor},
// 		tablewriter.Colors{tablewriter.FgYellowColor},
// 		tablewriter.Colors{tablewriter.FgBlueColor},
// 		tablewriter.Colors{tablewriter.FgRedColor},
// 	)
// 	table.SetColumnColor(
// 		tablewriter.Colors{tablewriter.FgGreenColor},
// 		tablewriter.Colors{tablewriter.FgCyanColor},
// 		tablewriter.Colors{tablewriter.FgYellowColor},
// 		tablewriter.Colors{tablewriter.FgBlueColor},
// 		tablewriter.Colors{tablewriter.FgRedColor},
// 	)

// 	// Lưu lại vị trí ban đầu của con trỏ
// 	// clearScreen()
// 	// moveCursorToStart()

// 	// Thêm từng dòng cho mỗi URL
// 	for _, urlInfo := range urlsInfo {
// 		status := fmt.Sprintf("%d", urlInfo.StatusCode)
// 		if urlInfo.StatusCode == 0 {
// 			status = "N/A"
// 		}

// 		// Add row
// 		table.Append([]string{
// 			urlInfo.Loc,
// 			status,
// 			urlInfo.LastMod,
// 			urlInfo.Changefreq,
// 			urlInfo.Priority,
// 		})

// 		// Di chuyển con trỏ về vị trí ban đầu và render bảng

// 	}
// 	//moveCursorToStart()
// 	table.Render()

// 	// Đợi một chút để quan sát sự thay đổi
// 	time.Sleep(1 * time.Second)
// 	// Hiển thị thông tin phân tích cuối cùng
// 	fmt.Println()
// 	fmt.Printf("Total URLs: %d\n", analysis.TotalURLs)
// 	fmt.Printf("Unique URLs: %d\n", analysis.UniqueURLs)
// 	fmt.Printf("Broken URLs: %d\n", analysis.BrokenURLs)
// }

// func main() {
// 	urls := []URLInfo{
// 		{Loc: "https://example.com/page1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "dailády", Priority: "0.8"},
// 		{Loc: "https://example.com/page1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "dfwefaily", Priority: "0.8"},
// 		{Loc: "https://example.cosadasdm/page1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "daily", Priority: "0.8"},
// 		{Loc: "https://example.com/dqwdqpage1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "daiwefly", Priority: "0.8"},
// 		{Loc: "https://example.coấm/page1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "daiely", Priority: "0.8"},
// 		{Loc: "https://example.com/page1", StatusCode: 2060, LastMod: "2023-10-01", Changefreq: "daily", Priority: "0.8"},
// 		{Loc: "https://example.com/pádage1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "dafeily", Priority: "0.8"},
// 		{Loc: "https://example.comđá/page1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "daeily", Priority: "0.8"},
// 		{Loc: "https://example.com/page1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "dailwfy", Priority: "0.8"},
// 		// {Loc: "https://example.comád/page1", StatusCode: 200, LastMod: "2023-10-01", Changefreq: "daidddddddlqy", Priority: "0.8"},
// 		// {Loc: "https://example.comád/page2", StatusCode: 404, LastMod: "2023-09-25", Changefreq: "weekly", Priority: "0.5"},
// 	}

// 	analysis := Analysis{TotalURLs: 2, UniqueURLs: 2, BrokenURLs: 1}
// 	displaySitemap(urls, analysis)
// }

// package main

// import (
// 	"fmt"
// 	"os"
// 	"time"

// 	"github.com/inancgumus/screen"
// 	"github.com/olekukonko/tablewriter"
// )

// type URLInfo struct {
// 	Loc        string
// 	StatusCode int
// 	LastMod    string
// 	Changefreq string
// 	Priority   string
// }

// type Analysis struct {
// 	TotalURLs  int
// 	UniqueURLs int
// 	BrokenURLs int
// }

// func displaySitemap(urlsInfo []URLInfo, analysis Analysis) {
// 	screen.Clear() // Xóa màn hình
// 	screen.MoveTopLeft()

// 	table := tablewriter.NewWriter(os.Stdout)
// 	table.SetHeader([]string{"URL", "Status", "Last Modified", "Changefreq", "Priority"})

// 	for _, urlInfo := range urlsInfo {
// 		status := fmt.Sprintf("%d", urlInfo.StatusCode)
// 		if urlInfo.StatusCode == 0 {
// 			status = "N/A"
// 		}
// 		table.Append([]string{urlInfo.Loc, status, urlInfo.LastMod, urlInfo.Changefreq, urlInfo.Priority})

// 		screen.Clear() // Xóa màn hình trước khi in lại
// 		screen.MoveTopLeft()
// 		table.Render() // In lại bảng

// 		// Hiển thị thông tin phân tích
// 		fmt.Printf("\nTotal URLs: %d\n", analysis.TotalURLs)
// 		fmt.Printf("Unique URLs: %d\n", analysis.UniqueURLs)
// 		fmt.Printf("Broken URLs: %d\n", analysis.BrokenURLs)

// 		time.Sleep(1 * time.Second) // Dừng một giây trước khi cập nhật tiếp
// 	}
// }

// func main() {
// 	// Dữ liệu mẫu
// 	urlsInfo := []URLInfo{
// 		{"https://example.com", 200, "2023-10-01", "daily", "0.8"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 		{"https://example.org", 404, "2023-09-30", "weekly", "0.5"},
// 	}

// 	analysis := Analysis{
// 		TotalURLs:  2,
// 		UniqueURLs: 2,
// 		BrokenURLs: 1,
// 	}

//		// Hiển thị bảng
//		displaySitemap(urlsInfo, analysis)
//	}
// package main

// import (
// 	"fmt"
// 	"log"
// 	"os"
// 	"time"

// 	ui "github.com/gizak/termui/v3"
// 	"github.com/gizak/termui/v3/widgets"
// )

// type URLInfo struct {
// 	URL          string
// 	Status       int
// 	LastModified string
// 	ChangeFreq   string
// 	Priority     float64
// }

// func displaySitemap(urlsInfo []URLInfo, analysis map[string]int) {
// 	if err := ui.Init(); err != nil {
// 		log.Fatalf("failed to initialize termui: %v", err)
// 	}
// 	defer ui.Close()

// 	table := widgets.NewTable()
// 	table.Rows = [][]string{
// 		{"URL", "Status", "Last Modified", "Changefreq", "Priority"},
// 	}

// 	// Thiết lập bảng
// 	table.TextStyle = ui.NewStyle(ui.ColorWhite)
// 	table.RowSeparator = true
// 	table.SetRect(0, 0, 70, 5)

// 	for _, url := range urlsInfo {
// 		// Cập nhật bảng
// 		//table.Append([]string{urlInfo.Loc, status, urlInfo.LastMod, urlInfo.Changefreq, urlInfo.Priority})
// 		table.Rows = append(table.Rows, []string{
// 			url.URL,
// 			string(url.Status),
// 			url.LastModified,
// 			url.ChangeFreq,
// 			fmt.Sprintf("%.1f", url.Priority),
// 		})
// 		table.SetRect(0, 0, 70, 7)

// 		// In ra bảng
// 		ui.Render(table)
// 		time.Sleep(1 * time.Second)
// 	}
// 	// Press Enter to continue
// 	//fmt.Print("Press Enter to continue...")
// 	os.Stdin.Read(make([]byte, 1))
// }

// func main() {
// 	urlsInfo := []URLInfo{
// 		{"https://examdddddddddddddple.com/bpage1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://examplbe.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.cobm/ffffffffffffffffpage1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.cbom/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.cobm/page1", 200, "2023-10-01", "daily", 0.8},
// 	}
// 	analysis := map[string]int{
// 		"TotalURLs":  2,
// 		"UniqueURLs": 2,
// 		"BrokenURLs": 1,
// 	}
// 	displaySitemap(urlsInfo, analysis)
// }

// package main

// import (
// 	"fmt"
// 	"os"
// 	"time"
// )

// type URLInfo struct {
// 	URL          string
// 	Status       int
// 	LastModified string
// 	ChangeFreq   string
// 	Priority     float64
// }

// func main() {
// 	urls := []URLInfo{
// 		{"https://example.cogm/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/bpage1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://examplbe.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.cobm/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.cbom/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.cobm/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.cbom/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", 0.8},
// 		{"https://example.com/page2", 404, "2023-09-25", "weekly", 0.5},
// 		// Add more URLInfo as needed
// 	}

// 	// Create a map to track seen URLs and avoid duplicates
// 	//seen := make(map[string]bool)

// 	// Print table header
// 	fmt.Println("+--------------------------------+--------+---------------+------------+----------+")
// 	fmt.Println("| URL                            | STATUS | LAST MODIFIED | CHANGEFREQ | PRIORITY |")
// 	fmt.Println("+--------------------------------+--------+---------------+------------+----------+")

// 	for _, urlInfo := range urls {
// 		// Check for duplicates
// 		//if !seen[urlInfo.URL] {
// 		//	seen[urlInfo.URL] = true
// 		fmt.Printf("| %-30s | %-6d | %-13s | %-10s | %-8.1f |\n", urlInfo.URL, urlInfo.Status, urlInfo.LastModified, urlInfo.ChangeFreq, urlInfo.Priority)
// 		fmt.Println("+--------------------------------+--------+---------------+------------+----------+")
// 		//}
// 		time.Sleep(time.Millisecond)
// 	}

//		// Press Enter to continue
//		fmt.Print("Press Enter to continue...")
//		os.Stdin.Read(make([]byte, 1))
//	}
// package main

// import "fmt"

//	func main() {
//		for false {
//			fmt.Println("1")
//		}
//	}
// package main

// import (
// 	"fmt"
// )

// // URLInfo lưu thông tin cho mỗi URL
// type URLInfo struct {
// 	Loc        string
// 	StatusCode int
// 	LastMod    string
// 	Changefreq string
// 	Priority   string
// }

// // Analysis lưu thông tin phân tích
// type Analysis struct {
// 	TotalURLs  int
// 	UniqueURLs int
// 	BrokenURLs int
// }

// // Hàm chia nhỏ chuỗi thành nhiều dòng nếu dài hơn maxLength
// func wrapString(s string, maxLength int) []string {
// 	var result []string
// 	for len(s) > maxLength {
// 		result = append(result, s[:maxLength])
// 		s = s[maxLength:]
// 	}
// 	if len(s) > 0 {
// 		result = append(result, s) // Thêm phần còn lại
// 	}
// 	return result
// }

// // Hàm hiển thị sitemap
// func displaySitemap(urlsInfo []URLInfo, analysis Analysis) {
// 	// Tạo header cho bảng
// 	fmt.Print("+---------------------------------+--------+---------------+------------+----------+\n")
// 	fmt.Print("|               URL               | STATUS | LAST MODIFIED | CHANGEFREQ | PRIORITY |\n")
// 	fmt.Print("+---------------------------------+--------+---------------+------------+----------+\n")

// 	// Thêm từng dòng cho mỗi URL
// 	for _, urlInfo := range urlsInfo {
// 		status := fmt.Sprintf("%d", urlInfo.StatusCode)
// 		if urlInfo.StatusCode == 0 {
// 			status = "N/A"
// 		}

// 		// Chia nhỏ các giá trị nếu cần
// 		wrappedURL := wrapString(urlInfo.Loc, 33)
// 		wrappedLastMod := wrapString(urlInfo.LastMod, 13)
// 		wrappedChangefreq := wrapString(urlInfo.Changefreq, 10)
// 		wrappedPriority := wrapString(urlInfo.Priority, 8)

// 		// In ra các dòng cho URL
// 		for i, urlPart := range wrappedURL {
// 			// Chỉ in ra dòng đầu tiên của URL với các giá trị khác
// 			if i == 0 {
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					urlPart, status,
// 					" ", " ", " ")
// 			} else {
// 				// In ra các dòng tiếp theo chỉ với URL
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					urlPart, " ",
// 					" ", " ", " ")
// 			}
// 			fmt.Print("+---------------------------------+--------+---------------+------------+----------+\n")
// 		}

// 		// In ra các giá trị còn lại
// 		// LAST MODIFIED
// 		for i, lastModPart := range wrappedLastMod {
// 			if i == 0 {
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					" ", status, lastModPart, " ", " ")
// 			} else {
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					" ", " ", lastModPart, " ", " ")
// 			}
// 			fmt.Print("+---------------------------------+--------+---------------+------------+----------+\n")
// 		}

// 		// CHANGEFREQ
// 		for i, changefreqPart := range wrappedChangefreq {
// 			if i == 0 {
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					" ", status, " ", changefreqPart, " ")
// 			} else {
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					" ", " ", " ", changefreqPart, " ")
// 			}
// 			fmt.Print("+---------------------------------+--------+---------------+------------+----------+\n")
// 		}

// 		// PRIORITY
// 		for i, priorityPart := range wrappedPriority {
// 			if i == 0 {
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					" ", status, " ", " ", priorityPart)
// 			} else {
// 				fmt.Printf("| %-33s | %-6s | %-13s | %-10s | %-8s |\n",
// 					" ", " ", " ", " ", priorityPart)
// 			}
// 			fmt.Print("+---------------------------------+--------+---------------+------------+----------+\n")
// 		}

// 		// Thêm một dòng trống giữa các URL
// 		fmt.Print("\n")
// 	}

// 	// Hiển thị thông tin phân tích
// 	fmt.Printf("Total URLs: %d\n", analysis.TotalURLs)
// 	fmt.Printf("Unique URLs: %d\n", analysis.UniqueURLs)
// 	fmt.Printf("Broken URLs: %d\n", analysis.BrokenURLs)
// }

// func main() {
// 	// Dữ liệu mẫu
// 	urlsInfo := []URLInfo{
// 		{"https://example.com/page1", 200, "2023-10-01", "daily", "0.8"},
// 		{"https://example.com/page2", 404, "2023-10-01", "weekly", "0.6"},
// 		{"https://example.com/pagggggadsdga", 200, "2023-10-01", "monthly", "0.4"},
// 		{"https://example.com/anotherlongurlthatshouldwrap", 200, "2022-12-05", "monthly", "0.4"},
// 	}

// 	analysis := Analysis{
// 		TotalURLs:  len(urlsInfo),
// 		UniqueURLs: len(urlsInfo), // Giả định là tất cả đều unique
// 		BrokenURLs: 1,             // Giả định có 1 broken URL
// 	}

//		// Hiển thị sitemap
//		displaySitemap(urlsInfo, analysis)
//	}
// package main

// import (
// 	"fmt"
// 	"os"
// )

//	func main() {
//		// for i := 1; i < 100; i++ {
//		// 	fmt.Println("11111111111111111111111111 ")
//		// 	fmt.Println("end " + strconv.Itoa(i))
//		// 	fmt.Println("end " + strconv.Itoa(i))
//		// 	fmt.Println("end " + strconv.Itoa(i))
//		// 	fmt.Println("end " + strconv.Itoa(i))
//		// 	fmt.Print("\033[F")
//		// 	fmt.Print("\033[F")
//		// 	fmt.Print("\033[F")
//		// 	fmt.Print("\033[F")
//		// 	// Thêm các ô khác...
//		// 	time.Sleep(1 * time.Second)
//		// }
//		fmt.Fprintf(os.Stderr, "%-15s : %s\n", "đâsdasdasd", "dsaasd")
//		fmt.Fprintf(os.Stderr, "%-15s : %s\n", "dsaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "dsaasd")
//	}

// func wrapText(value string, maxWidth int) []string {
// 	var result []string
// 	words := strings.Fields(value) // Chia chuỗi thành các từ
// 	currentLine := ""

// 	for _, word := range words {
// 		// Nếu thêm từ này vào dòng hiện tại sẽ vượt quá maxWidth
// 		if len(currentLine)+len(word)+1 > maxWidth {
// 			result = append(result, strings.TrimSpace(currentLine)) // Thêm dòng hiện tại vào kết quả
// 			currentLine = word                                      // Bắt đầu dòng mới với từ hiện tại
// 		} else {
// 			currentLine += " " + word // Thêm từ vào dòng hiện tại
// 		}
// 	}

// 	// Thêm dòng cuối cùng vào kết quả
// 	if currentLine != "" {
// 		result = append(result, strings.TrimSpace(currentLine))
// 	}

// 	return result
// }

// func printWithWrap(label string, value string, labelWidth int, valueWidth int) {
// 	// In dòng đầu tiên
// 	fmt.Fprintf(os.Stderr, "%-*s : %s\n", labelWidth, label, value)

// 	// Tạo các dòng còn lại cho value nếu nó dài hơn valueWidth
// 	wrappedLines := wrapText(value, valueWidth)
// 	for i := 1; i < len(wrappedLines); i++ {
// 		fmt.Fprintf(os.Stderr, "%-*s : %s\n", labelWidth, "", wrappedLines[i]) // Căn chỉnh với khoảng trắng
// 	}
// }

// package main

// import (
// 	"fmt"
// 	"io"
// 	"log"
// 	"net/http"

// 	wappalyzer "github.com/projectdiscovery/wappalyzergo"
// )

// func main() {
// 	resp, err := http.DefaultClient.Get("https://www.hackerone.com")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	data, _ := io.ReadAll(resp.Body) // Ignoring error for example

// 	wappalyzerClient, err := wappalyzer.New()
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	fingerprints := wappalyzerClient.Fingerprint(resp.Header, data)
// 	fmt.Printf("%v\n", fingerprints)
// 	// Output: map[Acquia Cloud Platform:{} Amazon EC2:{} Apache:{} Cloudflare:{} Drupal:{} PHP:{} Percona:{} React:{} Varnish:{}]

// 	fingerprintsWithCats := wappalyzerClient.FingerprintWithCats(resp.Header, data)
// 	fmt.Printf("%v\n", fingerprintsWithCats)

//		fingerprintsWithInfo := wappalyzerClient.FingerprintWithInfo(resp.Header, data)
//		fmt.Printf("%v\n", fingerprintsWithInfo)
//	}
// package main

// import (
// 	"context"

// 	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/installer"
// 	"github.com/projectdiscovery/nuclei/v3/pkg/output"
// 	"golang.org/x/tools/internal/event"
// )

// func main() {
// 	ctx := context.Background()
// 	// when running nuclei in parallel for first time it is a good practice to make sure
// 	// templates exists first
// 	tm := installer.TemplateManager{}
// 	if err := tm.FreshInstallIfNotExists(); err != nil {
// 		panic(err)
// 	}

// 	// create nuclei engine with options
// 	//ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx)
// 	ne, err := nuclei.NewNucleiEngineCtx(ctx,
// 		nuclei.WithTemplateFilters(nuclei.TemplateFilters{}),
// 		//nuclei.WithVerbosity(nuclei.VerbosityOptions{Verbose: true}),
// 	)
// 	if err != nil {
// 		panic(err)
// 	}
// 	// load targets and optionally probe non http/https targets
// 	ne.LoadTargets([]string{"hackerone.com"}, false)
// 	// when callback is nil it nuclei will print JSON output to stdout
// 	err = ne.ExecuteCallbackWithCtx(ctx, func(event *output.ResultEvent) {
// 		//fmt.Printf("[%s:%s] [%s] %s [%s]\n", event.TemplateID, event.Info.Name, event.Type, event.Host, event.ExtractedResults)
// 	})
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer ne.Close()
// 	// Output:
// 	// [dns-saas-service-detection] scanme.sh
// 	// [nameserver-fingerprint] scanme.sh
// 	// [dns-saas-service-detection] honey.scanme.sh
// }

package main

import (
	"context"
	"fmt"
	"os"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/remeh/sizedwaitgroup"
)

func main() {
	// Mở file để ghi, nếu file không tồn tại thì tạo mới, với quyền ghi và đọc
	file, err := os.OpenFile("testnuclei.txt", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("OpenFile")
	}
	defer file.Close()

	ctx := context.Background()
	// create nuclei engine with options
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(ctx)
	if err != nil {
		panic(err)
	}
	ne.GlobalLoadAllTemplates()
	// setup sizedWaitgroup to handle concurrency
	// here we are using sizedWaitgroup to limit concurrency to 1
	// but can be anything in general
	sg := sizedwaitgroup.New(1)

	// scan 2 = run dns templates on honey.scanme.sh
	sg.Add()
	go func() {
		defer sg.Done()
		err = ne.ExecuteNucleiWithOptsCtx(ctx, []string{"docs.hackerone.com", "honey.scanme.sh"},
			nuclei.WithTemplateFilters(nuclei.TemplateFilters{}),
		)

		if err != nil {
			panic(err)
		}
	}()
	ne.GlobalResultCallback(func(event *output.ResultEvent) {
		// Ghi dữ liệu vào file
		_, err = file.WriteString(event.Host + event.TemplateID)
		if err != nil {
			fmt.Println("WriteString")
		}
		fmt.Printf("\r Host: %s\n", event.Host)
		fmt.Printf("\r TemplateID: %s\n", event.TemplateID)
		fmt.Printf("\r ExtractorName: %s\n", event.ExtractorName)
		fmt.Printf("\r Matched: %s\n", event.Matched)
		fmt.Printf("\r MatcherName: %s\n", event.MatcherName)
		fmt.Printf("\r Type: %s\n", event.Type)
		fmt.Printf("\r Name: %s\n", event.Info.Name)
		if len(event.Info.Description) > 0 {
			fmt.Printf("\r Description: %s\n", event.Info.Description)
		}

		if len(event.Info.SeverityHolder.Severity.String()) > 0 {
			fmt.Printf("\r Severity: %s\n", event.Info.SeverityHolder.Severity)
		}

		if len(event.ExtractedResults) > 0 {
			fmt.Printf("\rExtracted Results: %v\n", event.ExtractedResults)
		}
		fmt.Printf("\r Classification: %v\n", event.Info.Classification)
		fmt.Printf("\r ********: \n")
	})
	// wait for all scans to finish
	sg.Wait()
	defer ne.Close()

}

// ne.GlobalResultCallback(func(event *output.ResultEvent) {
// 	//fmt.Printf("\r CURLCommand: %s\n", event.CURLCommand)
// 	//fmt.Printf("\r Error: %s\n", event.Error)
// 	fmt.Printf("\r ExtractorName: %s\n", event.ExtractorName)
// 	//fmt.Printf("\r FuzzingMethod: %s\n", event.FuzzingMethod)
// 	//fmt.Printf("\r FuzzingParameter: %s\n", event.FuzzingParameter)
// 	//fmt.Printf("\r FuzzingPosition: %s\n", event.FuzzingPosition)
// 	fmt.Printf("\r Host: %s\n", event.Host)
// 	fmt.Printf("\r IP: %s\n", event.IP)
// 	fmt.Printf("\r Matched: %s\n", event.Matched)
// 	fmt.Printf("\r MatcherName: %s\n", event.MatcherName)
// 	//fmt.Printf("\r Path: %s\n", event.Path)
// 	fmt.Printf("\r Port: %s\n", event.Port)
// 	//fmt.Printf("\r ReqURLPattern: %s\n", event.ReqURLPattern)
// 	//fmt.Printf("\r Request: %s\n", event.Request)
// 	// fmt.Printf("\r Response: %s\n", event.Response)
// 	//fmt.Printf("\r Scheme: %s\n", event.Scheme)
// 	//fmt.Printf("\r Template: %s\n", event.Template)
// 	//fmt.Printf("\r TemplateEncoded: %s\n", event.TemplateEncoded)
// 	fmt.Printf("\r TemplateID: %s\n", event.TemplateID)
// 	fmt.Printf("\r TemplatePath: %s\n", event.TemplatePath)
// 	//fmt.Printf("\r TemplateURL: %s\n", event.TemplateURL)
// 	//fmt.Printf("\r TemplateVerifier: %s\n", event.TemplateVerifier)
// 	fmt.Printf("\r Type: %s\n", event.Type)
// 	fmt.Printf("\r URL: %s\n", event.URL)
// 	//fmt.Printf("\r Authors: %s\n", event.Info.Authors)
// 	fmt.Printf("\r Name: %s\n", event.Info.Name)
// 	fmt.Printf("\r Tags: %s\n", event.Info.Tags)
// 	if len(event.Info.Description) > 0 {
// 		fmt.Printf("\r Description: %s\n", event.Info.Description)
// 	}
// 	//fmt.Printf("\r Impact: %s\n", event.Info.Impact)
// 	//fmt.Printf("\r Reference: %s\n", event.Info.Reference)
// 	//fmt.Printf("\r Remediation: %s\n", event.Info.Remediation)
// 	//fmt.Printf("\r CVEID: %s\n", event.Info.Classification.CVEID)
// 	if len(event.Info.Reference.StringSlice.String()) > 0 {
// 		fmt.Printf("\r StringSlice: %s\n", event.Info.Reference.StringSlice)
// 	}
// 	if len(event.Info.SeverityHolder.Severity.String()) > 0 {
// 		fmt.Printf("\r Severity: %s\n", event.Info.SeverityHolder.Severity)
// 	}
// 	fmt.Printf("\r Classification: %v\n", event.Info.Classification)
// 	if len(event.Info.Metadata) > 0 {
// 		fmt.Printf("\r Metadata: %s\n", event.Info.Metadata)
// 	}
// 	//fmt.Printf("\r SeverityHolder: %s\n", event.Info.SeverityHolder)
// 	//fmt.Printf("\r MatcherStatus: %v\n", event.MatcherStatus)
// 	if len(event.Metadata) > 0 {
// 		fmt.Printf("\r Metadata: %s\n", event.Metadata)
// 	}
// 	//fmt.Printf("\r Lines: %v\n", event.Lines)
// 	//fmt.Printf("\r IsFuzzingResult: %v\n", event.IsFuzzingResult)
// 	if len(event.ExtractedResults) > 0 {
// 		fmt.Printf("\rExtracted Results: %v\n", event.ExtractedResults)
// 	}
// 	fmt.Printf("\r ********: \n")
// })
