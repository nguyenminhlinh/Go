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

// 	fmt.Println("Giá trị của name:", osMatch.Name)
// 	fmt.Println("Giá trị của accuracy:", osMatch.Accuracy)
// }
