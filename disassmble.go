package main

import (
	"fmt"
	"os"
)

type modRM struct {
	mod   byte
	r     byte
	m     byte
	rname string
	mname string
}
type sib struct {
	ss    byte
	index byte
	base  byte
}
type linearAddress struct {
	segmentRegsiter string
	displacement    string
	indexRegister   string
	scale           byte
}
type instruction struct {
	opcode       byte
	opcodeString string
	modrm        byte
	modrmStruct  modRM
	sib          byte
	sibStruct    sib
	address      linearAddress
	immediate    string
}

func selectTypeOfCalc(buffer byte) (mnemonic string) {

	switch buffer >> 3 & 0x7 { //opcode
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
	return mnemonic
}
func numberToRegister(buffer byte) (ret string) {
	switch buffer {
	case 0x0:
		ret = "eax"
		break
	case 0x1:
		ret = "ecx"
		break
	case 0x2:
		ret = "edx"
		break
	case 0x3:
		ret = "ebx"
		break
	case 0x4:
		ret = "esp"
		break
	case 0x5:
		ret = "ebp"
		break
	case 0x6:
		ret = "esi"
		break
	case 0x7:
		ret = "edi"
		break
	default:
		break
	}
	return ret
}

func analyzeModRM(buffer byte) modRM {
	var modrm modRM
	modrm.mod = buffer >> 6
	modrm.r = buffer >> 3 & 0x7
	modrm.m = buffer & 0x7
	modrm.rname = numberToRegister(buffer >> 3 & 0x7)
	modrm.mname = numberToRegister(buffer & 0x7)
	return modrm
}

func main() {
	filename := os.Args[1]
	file, err := os.Open(filename)
	if err != nil {
		fmt.Println(err)
	}

	for {
		//var opcode, modrm, sib byte
		//var displacement, immediate string

		var instruction instruction
		var buffer8 = make([]byte, 1)
		len, err := file.Read(buffer8)
		instruction.opcode = buffer8[0]

		if err != nil {
			fmt.Println(err)
		}
		if len == 0 {
			break
		}

		switch instruction.opcode {
		case 0x50:
		case 0x51:
		case 0x52:
		case 0x53:
		case 0x54:
		case 0x55:
		case 0x56:
		case 0x57:
			instruction.opcodeString = "push"
			instruction.modrmStruct.rname = numberToRegister(instruction.opcode - 0x50)
			fmt.Printf("%s %s\n", instruction.opcodeString, instruction.modrmStruct.rname)
			break
		case 0x81:
			file.Read(buffer8)
			instruction.modrm = buffer8[0]
			instruction.opcodeString = selectTypeOfCalc(instruction.modrm)
			instruction.modrmStruct = analyzeModRM(instruction.modrm)
			instruction.address.segmentRegsiter = instruction.modrmStruct.mname
			var buffer32 = make([]byte, 4)
			var buffer = ""
			switch instruction.modrmStruct.mod {
			case 0x0:
				buffer = "[" + instruction.address.segmentRegsiter + "]"
			case 0x1:
				file.Read(buffer8)
				instruction.address.displacement = string(buffer8)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x2:
				file.Read(buffer32)
				instruction.address.displacement = string(buffer32)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x3:
				buffer = instruction.address.segmentRegsiter
			default:
				break
			}

			file.Read(buffer32)
			instruction.immediate = string(buffer32)
			fmt.Printf("%s %s, %s", instruction.opcodeString, buffer, instruction.immediate)
			break

		case 0x83:
			file.Read(buffer8)
			instruction.modrm = buffer8[0]
			instruction.opcodeString = selectTypeOfCalc(instruction.modrm)
			instruction.modrmStruct = analyzeModRM(instruction.modrm)
			instruction.address.segmentRegsiter = instruction.modrmStruct.mname
			var buffer32 = make([]byte, 4)
			var buffer = ""
			switch instruction.modrmStruct.mod {
			case 0x0:
				buffer = "[" + instruction.address.segmentRegsiter + "]"
			case 0x1:
				file.Read(buffer8)
				instruction.address.displacement = string(buffer8)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x2:
				file.Read(buffer32)
				instruction.address.displacement = string(buffer32)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x3:
				buffer = instruction.address.segmentRegsiter
			default:
				break
			}
			file.Read(buffer8)
			instruction.immediate = string(buffer8)
			fmt.Printf("%s %s, %s", instruction.opcodeString, buffer, instruction.immediate)
			break

		case 0x89:
			file.Read(buffer8)
			instruction.modrm = buffer8[0]
			instruction.opcodeString = "mov"
			instruction.modrmStruct = analyzeModRM(instruction.modrm)
			instruction.address.segmentRegsiter = instruction.modrmStruct.mname
			var buffer32 = make([]byte, 4)
			var buffer = ""
			switch instruction.modrmStruct.mod {
			case 0x0:
				buffer = "[" + instruction.address.segmentRegsiter + "]"
			case 0x1:
				file.Read(buffer8)
				instruction.address.displacement = string(buffer8)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x2:
				file.Read(buffer32)
				instruction.address.displacement = string(buffer32)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x3:
				buffer = instruction.address.segmentRegsiter
			default:
				break
			}
			fmt.Printf("%s %s, %s\n", instruction.opcodeString, buffer, instruction.modrmStruct.rname)
			break

		case 0x8b:
			file.Read(buffer8)
			instruction.modrm = buffer8[0]
			instruction.opcodeString = "mov"
			instruction.modrmStruct = analyzeModRM(instruction.modrm)
			instruction.address.segmentRegsiter = instruction.modrmStruct.mname
			var buffer32 = make([]byte, 4)
			var buffer = ""
			switch instruction.modrmStruct.mod {
			case 0x0:
				buffer = "[" + instruction.address.segmentRegsiter + "]"
			case 0x1:
				file.Read(buffer8)
				instruction.address.displacement = string(buffer8)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x2:
				file.Read(buffer32)
				instruction.address.displacement = string(buffer32)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x3:
				buffer = instruction.address.segmentRegsiter
			default:
				break
			}
			fmt.Printf("%s %s, %s\n", instruction.opcodeString, instruction.modrmStruct.rname, buffer)
			break

		case 0x90:
			instruction.opcodeString = "nop"
			fmt.Println(instruction.opcodeString)

		case 0xc7:
			file.Read(buffer8)
			instruction.modrm = buffer8[0]
			instruction.opcodeString = "mov"
			instruction.modrmStruct = analyzeModRM(instruction.modrm)
			instruction.address.segmentRegsiter = instruction.modrmStruct.mname
			var buffer32 = make([]byte, 4)
			var buffer = ""
			switch instruction.modrmStruct.mod {
			case 0x0:
				buffer = "[" + instruction.address.segmentRegsiter + "]"
			case 0x1:
				file.Read(buffer8)
				instruction.address.displacement = string(buffer8)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x2:
				file.Read(buffer32)
				instruction.address.displacement = string(buffer32)
				buffer = "[" + instruction.address.segmentRegsiter + "+0x" + instruction.address.displacement + "]"
				break
			case 0x3:
				buffer = instruction.address.segmentRegsiter
			default:
				break
			}
			file.Read(buffer32)
			instruction.immediate = string(buffer32)
			fmt.Printf("%s %s, %s\n", instruction.opcodeString, buffer, instruction.immediate)
			break
		}

	}
}
