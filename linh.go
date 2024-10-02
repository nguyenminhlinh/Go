// package main

// import (
// 	"encoding/xml"
// 	"fmt"
// )

// type OsMatch struct {
// 	Name     string `xml:"name,attr"`
// 	Accuracy string `xml:"accuracy,attr"`
// }

// func main() {
// 	xmlData := `<osmatch name="Linux 5.0 - 5.14" accuracy="100" line="71713"></osmatch>`

// 	var osMatch OsMatch
// 	err := xml.Unmarshal([]byte(xmlData), &osMatch)
// 	if err != nil {
// 		fmt.Println("Lỗi khi phân tích cú pháp XML:", err)
// 		return
// 	}

//		fmt.Println("Giá trị của name:", osMatch.Name)
//		fmt.Println("Giá trị của accuracy:", osMatch.Accuracy)
//	}
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/likexian/whois"
	whoisparser "github.com/likexian/whois-parser"
)

type IPInfo struct {
	Country string `json:"country"`
}

func getCountryByIP(ip string) (string, error) {
	resp, err := http.Get("http://ip-api.com/json/" + ip)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", err
	}
	return info.Country, nil
}

func main() {
	ip := "tryhackme.com" // Thay thế bằng IP thực tế
	country, err := getCountryByIP(ip)
	if err != nil {
		fmt.Println("Lỗi khi lấy thông tin quốc gia:", err)
		return
	}
	fmt.Println("Quốc gia của IP:", country)

	domain := "hackerone.com"

	// Thực hiện tra cứu WHOIS
	result, err := whois.Whois(domain)
	if err != nil {
		log.Fatalf("Lỗi khi thực hiện tra cứu WHOIS: %v", err)
	}

	// Phân tích dữ liệu WHOIS
	parsedResult, err := whoisparser.Parse(result)
	if err != nil {
		log.Fatalf("Lỗi khi phân tích kết quả WHOIS: %v", err)
	}

	// In thông tin quốc gia
	if parsedResult.Registrant.Country != "" {
		fmt.Println("Quốc gia của người đăng ký:", parsedResult.Registrant.Country)
	} else {
		fmt.Println("Không tìm thấy thông tin quốc gia.")
	}
}
