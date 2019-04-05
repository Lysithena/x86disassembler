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
type effectiveAddress struct {
	displacement  string
	indexRegister byte
	scale         byte
	baseRegister  byte
}
type linearAddress struct {
	segmentRegsiter  string
	effectiveAddress effectiveAddress
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

func getSizeOfArg(buffer byte) (ret int) {
	switch buffer {
	case 0x1:
		ret = 1
	case 0x2:
		ret = 4
	default:
		ret = 0
	}
	return ret
}
func formatMnemonicMImm(instruction instruction) (ret string) {
	switch instruction.modrmStruct.mod {
	case 0x0:
		fallthrough
	case 0x1:
		fallthrough
	case 0x2:
		ret = fmt.Sprintf("%s [%s %s], %s", instruction.opcodeString,
			instruction.address.segmentRegsiter,
			instruction.address.effectiveAddress.displacement,
			instruction.immediate)
	case 0x3:
		ret = fmt.Sprintf("%s %s, %s", instruction.opcodeString,
			instruction.address.segmentRegsiter,
			instruction.immediate)
	}
	return ret
}
func formatMnemonicMR(instruction instruction) (ret string) {
	switch instruction.modrmStruct.mod {
	case 0x0:
		fallthrough
	case 0x1:
		fallthrough
	case 0x2:
		ret = fmt.Sprintf("%s [%s %s], %s", instruction.opcodeString,
			instruction.address.segmentRegsiter,
			instruction.address.effectiveAddress.displacement,
			instruction.modrmStruct.rname)
	case 0x3:
		ret = fmt.Sprintf("%s %s, %s", instruction.opcodeString,
			instruction.address.segmentRegsiter,
			instruction.modrmStruct.rname)
	}
	return ret
}
func formatMnemonicRM(instruction instruction) (ret string) {
	switch instruction.modrmStruct.mod {
	case 0x0:
		fallthrough
	case 0x1:
		fallthrough
	case 0x2:
		ret = fmt.Sprintf("%s %s, [%s %s]", instruction.opcodeString,
			instruction.modrmStruct.rname,
			instruction.address.segmentRegsiter,
			instruction.address.effectiveAddress.displacement)
	case 0x3:
		ret = fmt.Sprintf("%s %s, %s", instruction.opcodeString,
			instruction.modrmStruct.rname,
			instruction.address.segmentRegsiter)
	}
	return ret
}
func formatSingleMnemonic(instruction instruction) (ret string) {
	ret = fmt.Sprintf("%s", instruction.opcodeString)
	return ret
}
func initializeInstruction(modrm byte) instruction {
	var instruction instruction
	instruction.modrm = modrm
	instruction.modrmStruct = analyzeModRM(instruction.modrm)
	instruction.address.segmentRegsiter = instruction.modrmStruct.mname
	return instruction
}

func bigEndian2LittleEndian(buffer []byte) (ret string) {
	var temp int32
	switch len(buffer) {
	case 1:
		temp = int32(int8(buffer[0]))
	default:
		for i := uint32(0); i < uint32(len(buffer)); i++ {
			//fmt.Println(buffer[i])
			temp += int32(int8(buffer[i])) << (i * 8)
		}
	}
	ret = fmt.Sprintf("%x", temp)
	return ret
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
		var opcode = make([]byte, 1)
		var modrm = make([]byte, 1)
		len, err := file.Read(opcode)
		instruction.opcode = opcode[0]

		if err != nil {
			fmt.Println(err)
		}
		if len == 0 {
			break
		}
		fmt.Printf("%02x\t", instruction.opcode)
		switch instruction.opcode {
		case 0x01:
			file.Read(modrm)
			instruction = initializeInstruction(modrm[0])
			instruction.opcodeString = "add"
			fmt.Println(formatMnemonicMR(instruction))
		case 0x50:
			fallthrough
		case 0x51:
			fallthrough
		case 0x52:
			fallthrough
		case 0x53:
			fallthrough
		case 0x54:
			fallthrough
		case 0x55:
			fallthrough
		case 0x56:
			fallthrough
		case 0x57:
			instruction.opcodeString = "push"
			instruction.modrmStruct.rname = numberToRegister(instruction.opcode - 0x50)
			fmt.Printf("%s %s\n", instruction.opcodeString, instruction.modrmStruct.rname)
			break

		case 0x81:
			file.Read(modrm)
			instruction = initializeInstruction(modrm[0])
			instruction.opcodeString = selectTypeOfCalc(instruction.modrm)
			var buffer = make([]byte, getSizeOfArg(instruction.modrmStruct.mod))
			var buffer32 = make([]byte, 4)

			file.Read(buffer)
			instruction.address.effectiveAddress.displacement = bigEndian2LittleEndian(buffer)
			file.Read(buffer32)
			instruction.immediate = string(buffer32)
			fmt.Println(formatMnemonicMImm(instruction))

		case 0x83:
			file.Read(modrm)
			instruction = initializeInstruction(modrm[0])
			instruction.opcodeString = selectTypeOfCalc(instruction.modrm)
			var displacement = make([]byte, getSizeOfArg(instruction.modrmStruct.mod))
			var immediate = make([]byte, 1)

			file.Read(displacement)
			instruction.address.effectiveAddress.displacement = bigEndian2LittleEndian(displacement)
			file.Read(immediate)
			instruction.immediate = bigEndian2LittleEndian(immediate)
			fmt.Println(formatMnemonicMImm(instruction))

		case 0x89:
			file.Read(modrm)
			instruction = initializeInstruction(modrm[0])
			instruction.opcodeString = "mov"
			instruction.modrmStruct = analyzeModRM(instruction.modrm)
			var displacement = make([]byte, getSizeOfArg(instruction.modrmStruct.mod))

			file.Read(displacement)
			instruction.address.effectiveAddress.displacement = bigEndian2LittleEndian(displacement)
			fmt.Println(formatMnemonicMR(instruction))

		case 0x8b:
			file.Read(modrm)
			instruction = initializeInstruction(modrm[0])
			instruction.opcodeString = "mov"
			instruction.modrmStruct = analyzeModRM(instruction.modrm)
			var displacement = make([]byte, getSizeOfArg(instruction.modrmStruct.mod))

			file.Read(displacement)
			instruction.address.effectiveAddress.displacement = bigEndian2LittleEndian(displacement)
			fmt.Println(formatMnemonicRM(instruction))

		case 0x90:
			instruction.opcodeString = "nop"
			fmt.Println(instruction.opcodeString)
			break

		case 0xb8:
			fallthrough
		case 0xb9:
			fallthrough
		case 0xba:
			fallthrough
		case 0xbb:
			fallthrough
		case 0xbc:
			fallthrough
		case 0xbd:
			fallthrough
		case 0xbe:
			fallthrough
		case 0xbf:
			instruction.opcodeString = "mov"
			instruction.address.segmentRegsiter = numberToRegister(instruction.opcode - 0xb8)
			instruction.modrmStruct.mod = 3
			var immidiate = make([]byte, 4)
			file.Read(immidiate)
			instruction.immediate = bigEndian2LittleEndian(immidiate)
			fmt.Println(formatMnemonicMImm(instruction))
			break

		case 0xc7:
			file.Read(modrm)
			instruction = initializeInstruction(modrm[0])
			instruction.opcodeString = "mov"
			var buffer = make([]byte, getSizeOfArg(instruction.modrmStruct.mod))
			var buffer32 = make([]byte, 4)

			file.Read(buffer)
			instruction.address.effectiveAddress.displacement = bigEndian2LittleEndian(buffer)
			file.Read(buffer32)
			instruction.immediate = bigEndian2LittleEndian(buffer32)
			fmt.Println(formatMnemonicMImm(instruction))

		case 0xc3:
			instruction.opcodeString = "ret"
			fmt.Println(formatSingleMnemonic(instruction))
		case 0xc9:
			instruction.opcodeString = "leave"
			fmt.Println(formatSingleMnemonic(instruction))
		default:
			fmt.Println("Unknown!")
		}
	}
}
