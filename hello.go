package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func dig(domain string, qtype uint16) {
	// Create a DNS message
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), qtype)
	msg.RecursionDesired = true

	// Select the DNS server to query
	dnsServer := "8.8.8.8:53" //Use Google DNS

	// Create a client to send DNS requests
	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	// Send DNS requests
	response, rtt, err := client.Exchange(msg, dnsServer)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}

	// Check DNS status code (Rcode)
	fmt.Printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d\n", dns.RcodeToString[response.Rcode], response.Id)
	fmt.Printf(";; query time: %v msec\n", rtt.Milliseconds())
	fmt.Println(response.Answer)
	// Print the response if the status is NOERROR
	if response.Rcode == dns.RcodeSuccess {
		//fmt.Println(response.Answer)
		// for _, answer := range response.Answer {
		// 	fmt.Println(answer.String())
		// }
	} else {
		fmt.Printf("Query failed with status: %s\n", dns.RcodeToString[response.Rcode])
	}
}

func test(ctx context.Context, wg *sync.WaitGroup, semaphore chan string, results chan<- string, count *int, mu *sync.Mutex) {
	defer wg.Done()
	for {
		time.Sleep(1 * time.Second)
		select {
		case <-ctx.Done():
			mu.Lock()
			*count++
			fmt.Println("Context cancelled, stopping file test.")
			// Nếu nhận tín hiệu hủy từ context, đóng semaphore và thoát

			fmt.Println(*count)
			if *count == 10 {
				close(results)
				fmt.Println("stopping file test.")
				for len(semaphore) > 0 {
					<-semaphore // Đọc và bỏ qua dữ liệu cho đến khi channel trống
				}

			}
			mu.Unlock()
			return
		default:
			subdomain, ok := <-semaphore
			fmt.Println("Error reading file:")
			if !ok {
				return
			} else {
				results <- subdomain + "*"
			}
		}
	}
}
func readFiles(ctx context.Context, wg *sync.WaitGroup, wordlist string, semaphore chan<- string) {
	defer wg.Done()

	file, err := os.Open(wordlist)
	if err != nil {
		fmt.Println("Error opening file:", err)
		close(semaphore)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for {
		select {
		case <-ctx.Done():
			// Nếu nhận tín hiệu hủy từ context, đóng semaphore và thoát
			fmt.Println("Context cancelled, stopping file read.")
			close(semaphore)
			return
		default:
			if !scanner.Scan() {
				// Đọc xong file hoặc gặp lỗi
				if err := scanner.Err(); err != nil {
					fmt.Println("Error reading file:", err)
				}
				close(semaphore)
				return
			}
			domain := scanner.Text()
			semaphore <- domain // Gửi domain vào channel semaphore để kiểm tra
		}
	}
}

func BruteDomainDNS(ctx context.Context, cancel context.CancelFunc, wordlist string) {
	//Đọc wordlists từ file
	var wg sync.WaitGroup
	var count int
	var mu sync.Mutex
	semaphore := make(chan string, 10)
	results := make(chan string, 10)
	wg.Add(1)
	go readFiles(ctx, &wg, wordlist, semaphore)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go test(ctx, &wg, semaphore, results, &count, &mu)
	}

	wg.Add(1)
	go writeFiles(ctx, &wg, results, "linh.txt")
	wg.Wait()
}

// func output(ctx context.Context, wg *sync.WaitGroup, results chan string) {
// 	defer wg.Done()
// 	for {
// 		time.Sleep(1 * time.Second)
// 		select {
// 		case result, ok := <-results:
// 			if !ok {
// 				fmt.Println("hết write")
// 				//close(results)
// 				return
// 			}
// 			fmt.Println("out", result)
// 		case <-ctx.Done(): // Nếu nhận được tín hiệu hủy từ context
// 			fmt.Println("Context cancelled, stopping file write.")
// 			return
// 		}
// 	}
// }

func writeFiles(ctx context.Context, wg *sync.WaitGroup, results <-chan string, ouputFile string) {
	defer wg.Done()
	// Mở file để ghi kết quả
	file, err := os.OpenFile(ouputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("Error opening output file:", err)
		return
	}
	defer file.Close()

	for {
		select {
		// case <-ctx.Done(): // Nếu nhận được tín hiệu hủy từ context
		// 	fmt.Println("Context cancelled, stopping file write.")
		// 	return
		case result, ok := <-results:
			if !ok {
				fmt.Println("hết write")
				return
			}
			time.Sleep(1 * time.Second)
			_, err := file.Write([]byte(result))
			fmt.Println("write", result)
			if err != nil {
				fmt.Println("Error writing to file:", err)
			}
		}
	}
}

func main() {

	if len(os.Args) < 2 {
		fmt.Println("Usage: go-dig <domain>")
		os.Exit(1)
	}

	domain := os.Args[1]

	// Truy vấn A record
	fmt.Printf("A Record cho %s:\n", domain)
	dig(domain, dns.TypeA)

	// Truy vấn MX record
	fmt.Printf("\nMX Record cho %s:\n", domain)
	dig(domain, dns.TypeMX)

	// Truy vấn NS record
	fmt.Printf("\nNS Record cho %s:\n", domain)
	dig(domain, dns.TypeNS)

	// Truy vấn CNAME record
	fmt.Printf("\nCNAME Record cho %s:\n", domain)
	dig(domain, dns.TypeCNAME)

	// Truy vấn SOA record
	fmt.Printf("\nSOA Record cho %s:\n", domain)
	dig(domain, dns.TypeSOA)

	fmt.Printf("\nTXT Record cho %s:\n", domain)
	dig(domain, dns.TypeTXT)
	// ctx, cancel := context.WithCancel(context.Background())
	// defer cancel()

	// // Bắt tín hiệu Ctrl+C từ người dùng
	// c := make(chan os.Signal, 1)
	// signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	// go func() {
	// 	<-c
	// 	fmt.Println("Received Ctrl+C, canceling all tasks...")
	// 	cancel() // Hủy tất cả các goroutine đang chạy
	// }()

	// var wg sync.WaitGroup
	// wg.Add(1)
	// go func() {
	// 	BruteDomainDNS(ctx, cancel, "C:\\Users\\minhl\\recon\\src\\data\\input\\combined_subdomains.txt")
	// 	fmt.Println("17")
	// 	wg.Done()
	// }()

	// wg.Wait()

}
