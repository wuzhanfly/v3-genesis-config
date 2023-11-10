package main

//import the required packages
import (
	"fmt"
	"math/big"
	"strings"
)

func isDecimal(hexaString string) string {
	number := strings.Replace(hexaString, "0x", "", -1)
	number = strings.Replace(number, "0X", "", -1)
	return number
}
func main23() {

	hexaDecimal_num := "0xa968163f0a57b000000"
	result := isDecimal(hexaDecimal_num)
	//output, err := strconv.ParseUint(result, 16, 64)
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	// printing the result on the screen
	//fmt.Println("hex:", hexaDecimal_num, "is", output)

	i := new(big.Int)
	i.SetString(result, 16)
	fmt.Println(i) // 10
}
