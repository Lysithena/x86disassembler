package x86disassembler

import (
	"fmt"
	"os"
)

type modRM struct {
	mod   byte
	R     byte
	M     byte
	Rname string
	Mname string
}

func analyzeModRMOfCalc(buffer []byte) (mnemonic string) {

	switch buffer[0] >> 3 & 0x7 { //opcode
	case 0x0:
		mnemonic += "add"
		break
	case 0x1:
		mnemonic += "or"
		break
	case 0x2:
		mnemonic += "adc"
		break
	case 0x3:
		mnemonic += "sbb"
		break
	case 0x4:
		mnemonic += "and"
		break
	case 0x5:
		mnemonic += "sub"
		break
	case 0x6:
		mnemonic += "xor"
		break
	case 0x7:
		mnemonic += "cmp"
		break
	}
	mnemonic += " "
	modrm := analyzeModRM(buffer)
	mnemonic += modrm.Mname + " "
	return mnemonic
}

func analyzeModRM(buffer []byte) modRM {
	var modrm modRM
	modrm.mod = buffer[0] >> 6
	modrm.R = buffer[0] >> 3 & 0x7
	modrm.M = buffer[0] & 0x7
	switch buffer[0] >> 3 & 0x7 {
	case 0x0:
		modrm.Rname = "eax"
		break
	case 0x1:
		modrm.Rname = "ecx"
		break
	case 0x2:
		modrm.Rname = "edx"
		break
	case 0x3:
		modrm.Rname = "ebx"
		break
	case 0x4:
		modrm.Rname = "esp"
		break
	case 0x5:
		modrm.Rname = "ebp"
		break
	case 0x6:
		modrm.Rname = "esi"
		break
	case 0x7:
		modrm.Rname = "edi"
		break
	}
	switch buffer[0] & 0x7 {
	case 0x0:
		modrm.Mname = "eax"
		break
	case 0x1:
		modrm.Mname = "ecx"
		break
	case 0x2:
		modrm.Mname = "edx"
		break
	case 0x3:
		modrm.Mname = "ebx"
		break
	case 0x4:
		modrm.Mname = "esp"
		break
	case 0x5:
		modrm.Mname = "ebp"
		break
	case 0x6:
		modrm.Mname = "esi"
		break
	case 0x7:
		modrm.Mname = "edi"
		break
	}
	return modrm
}
func getArgumentsizeFromMod(modrm modRM) (size byte) {
	switch modrm.mod {
	case 0x01:
		return 1
	case 0x2:
		return 4
	default:
		return 0
	}
}
func getMnemonicFromMod(modrm modRM, argument []byte, mode bool) (mnemonic string) {
	if mode {
		switch modrm.mod {
		case 0x00:
			mnemonic += "[" + modrm.Rname + "], " + modrm.Mname
			break
		case 0x01:
		case 0x02:
			mnemonic += "[" + modrm.Rname + " +0x" + string(argument) + "], " + modrm.Mname
			break
		case 0x03:
			mnemonic += modrm.Rname + ", " + modrm.Mname
			break
		default:
			mnemonic += "Error"
		}
		return mnemonic
	} else {
		switch modrm.mod {
		case 0x00:
			mnemonic += modrm.Rname + ", [" + modrm.Mname + "]"
			break
		case 0x01:
		case 0x02:
			mnemonic += modrm.Rname + ", [" + modrm.Mname + " +0x" + string(argument) + "]"
			break
		case 0x03:
			mnemonic += modrm.Rname + ", " + modrm.Mname
			break
		default:
			mnemonic += "Error"
		}
		return mnemonic
	}
}
func getMnemonicFromType(buffer []byte, file *os.File, mode bool) (mnemonic string) {
	modrm := analyzeModRM(buffer)
	var temp = make([]byte, getArgumentsizeFromMod(modrm))
	file.Read(temp)
	mnemonic += getMnemonicFromMod(modrm, temp, mode)
	return mnemonic
}
func main() {
	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}

	for {
		var buffer = make([]byte, 1)
		len, err := file.Read(buffer)
		if err != nil {
			fmt.Println(err)
		}
		if len == 0 {
			break
		}
		var mnemonic string

		switch buffer[0] {
		case 0x01:
			mnemonic += "add "
			file.Read(buffer)
			getMnemonicFromType(buffer, file, true)
		case 0x81:
			mnemonic += "calc- "
			file.Read(buffer)
			mnemonic += analyzeModRMOfCalc(buffer)
			for i := 0; i < 4; i++ {
				file.Read(buffer)
				mnemonic += string(buffer)
			}
			break
		case 0x83:
			mnemonic += "calc-"
			file.Read(buffer)
			mnemonic += analyzeModRMOfCalc(buffer)
			file.Read(buffer)
			mnemonic += string(buffer)
			break
		case 0x89:
			mnemonic += "mov"
			file.Read(buffer)
			getMnemonicFromType(buffer, file, true)
		case 0x8b:
			mnemonic += "mov"
			file.Read(buffer)
			getMnemonicFromType(buffer, file, false)
		case 0xc7:
			mnemonic += "mov"
			file.Read(buffer)
			mnemonic += getMnemonicFromType(buffer, file, true)
			//つんだ [register + immidiate],immidiate型に対応してない
		}

	}
}
