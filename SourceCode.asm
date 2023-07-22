TITLE Assignment 1

; Author	:: Charith Akalanka
; StudentID :: 103800782

INCLUDE Irvine32.inc

PBYTE TYPEDEF PTR BYTE

bufferMax = 200

.data
prompt0		BYTE "========================================================", 0dh, 0ah
			BYTE "|                                                      |", 0dh, 0ah
			BYTE "|    CYB80003 - Advanced Cyber Security Programming    |", 0dh, 0ah
			BYTE "|                      ASSIGNMENT                      |", 0dh, 0ah
			BYTE "|                                                      |", 0dh, 0ah
			BYTE "|             Created by: Charith Akalanka             |", 0dh, 0ah
			BYTE "|             Student ID: 103800782                    |", 0dh, 0ah
			BYTE "|                                                      |", 0dh, 0ah
			BYTE "========================================================", 0dh, 0ah
			BYTE 0ah, 0
promptID	BYTE "Enter your student ID [1-30]: ", 0
promptBadID BYTE " Student ID is invalid ", 0dh, 0ah, 0
studentID	DWORD 0
IDbuffer	BYTE 10 DUP(0)
studentIDString PBYTE ?
promptPass	BYTE "Enter the password	: ", 0
promptFname BYTE "Enter your first name	: ", 0
promptLname BYTE "Enter your last name	: ", 0
promptDob	BYTE "Enter your date of birth [ Press Enter to Retry ]", 0dh, 0ah
			BYTE "  (Format: DD/MM/YYYY): ", 0
passKey		DWORD 20
passSeed	DWORD 0
pass1		BYTE "DTggc$fp", 0					; Encrypted password (P@ssw0rd)
passBad		BYTE "========================================================", 0dh, 0ah
			BYTE "|           Password Incorrect. Try again              |", 0dh, 0ah
			BYTE "|                   [ ^C to Exit ]                     |", 0dh, 0ah
			BYTE "========================================================", 0dh, 0ah
			BYTE 0ah, 0
passGood	BYTE "========================================================", 0dh, 0ah
			BYTE "|                                                      |", 0dh, 0ah
			BYTE "|                    Access Granted                    |", 0dh, 0ah
			BYTE "|                                                      |", 0dh, 0ah
			BYTE "========================================================", 0dh, 0ah
			BYTE 0ah, 0
buffer		BYTE bufferMax DUP(0)
fname		BYTE 20 dup(0), 0
lname		BYTE 20 dup(0), 0
dob			BYTE 10 dup(0), 0
filename	BYTE "details.txt"
fileHandle	HANDLE ?
fileFound	BYTE "========================================================", 0dh, 0ah
			BYTE "|        Data written to the 'details.txt' file        |", 0dh, 0ah
			BYTE "========================================================", 0dh, 0ah
			BYTE 0ah, 0

fileNotFound BYTE "========================================================", 0dh, 0ah
			BYTE "|          Creating a new 'detials.txt' file           |", 0dh, 0ah
			BYTE "========================================================", 0dh, 0ah
			BYTE 0ah, 0

fileLine1	BYTE "********************************************************", 0dh, 0ah, 0
fileLine2	BYTE 09h, "Student ID    : ", 0
fileLine3	BYTE 09h, "Full Name     : ", 0
fileLine4	BYTE 09h, "Date of Birth : ", 0
fileLine5	BYTE 09h, "Password      : ", 0
fileSpace	BYTE 20h, 0
fileLineSep BYTE 0dh, 0ah, 0

.code
main PROC
	call	WelcomeMsg
	call	RetrieveSid
	call	ConvertIntToString
	call	VerifyPass
	call	GetDetails
	call	ClearBuffer
	call	CreateDataString
	call	WriteDetails
	call	ReadChar
	exit

main ENDP

;-------------------------------------------------------------------------
  WelcomeMsg PROC

; PURPOSE	: Print the welcome message
; RECIEVES	: Nothing
; RETURNS	: Nothing
;-------------------------------------------------------------------------
	mov		edx, OFFSET prompt0
	call	WriteString
	ret
WelcomeMsg ENDP

;-------------------------------------------------------------------------
  RetrieveSid PROC

; PURPOSE	: Retrieve student ID
; RECIEVES	: Nothing
; RETURNS	: Nothing
;-------------------------------------------------------------------------
L1:
	mov		edx, OFFSET promptID
	call	WriteString
	call	ReadDec					; If input is an integer the value is returned in EAX. Else EAX=0
	cmp		eax, 1
	jb		BAD						; Entered ID is invalid or less than 1
	cmp		eax, 30
	ja		BAD						; Entered ID is greater than 30
	jmp GOOD
BAD:
	mov		eax, red+(white*16)		; Change text and background colors for the error message
    call	SetTextColor
	mov		edx, OFFSET promptBadID
	call	WriteString
	mov		eax, white+(black*16)
    call	SetTextColor			; Restore the default text and background colors
	jmp L1
GOOD:
	mov		StudentID, eax
	ret
RetrieveSid ENDP

;-----------------------------------------------------
  ConvertIntToString PROC
;
; PURPOSE : Converts an unsigned integer value to an Integer string.
;			Used to convert the userID into a printable format.
;			Adopted from the source code for WriteDec and WriteInt
;			procedures in Irvine32 library.
;------------------------------------------------------

	mov		ecx, 0					; digit counter
	mov		edi, OFFSET IDbuffer
	add		edi, (LENGTHOF IDbuffer-2) 
									; Go to the end of the buffer, 
									; -1 because offset is in Zero index 
									; -1 to make space for the NULL terminator

	mov		ebx, 10					; decimal number base

WI1:mov		edx,0					; clear dividend to zero
	div		ebx            			; divide EAX by the radix
	add		dl, 30h					; convert DL to ASCII
	mov		[edi], dl      			; save the digit
	dec		edi            			; back up in buffer

	inc		ecx            			; increment digit count
	or		eax,eax        			; quotient = 0?
	jnz		WI1            			; no, divide again

WI3:
	 inc	edi
	 mov	edx,edi
	 mov	studentIDString, edi
	 ret

ConvertIntToString ENDP

;-------------------------------------------------------------------------
  Crypt PROC

; PURPOSE	: Encrypt/Decrypt a given input.
;			  Used to decypt the password in runtime. Text is decrypted in its memory location
;			  Adopted from Encrypt.asm by Kip Irvine (Chapter 6, Page 198)
; RECIEVES	: Key in ESI, Text offset in EDI, Text length in ECX
; RETURNS	: Nothing
;-------------------------------------------------------------------------
	sub		ecx, 1					; -1 from char count to account for the null character
L1:
	mov		eax, [edi]				; Read the character to eax
	xor		eax, esi				; XOR EAX with the Key
	mov		[edi], eax				; Replace character with the new value 
	inc		edi						; Increment the character index
	LOOP L1							; Loop until all the characters are processed
	ret
crypt ENDP

;------------------------------------------------------
  VerifyPass PROC

; PURPOSE	: Retrieve password and verify. Password is read one Char at a time.
;			  User input is hidden, but characters are indicated by *
; RECIEVES	: Nothing
; RETURNS	: Nothing
;------------------------------------------------------
	mov		esi, passKey
	mov		edi, OFFSET pass1
	mov		ecx, LENGTHOF pass1
	call	Crypt					; Decrypt the password before verification

START:
	mov		edx, OFFSET promptPass
	call	WriteString
	mov		edi, OFFSET buffer
L1:
	call	ReadChar
	cmp		al, 0					; Extended key entered. Disregard
	je		L1
	cmp		al, 13					; ENTER key pressed. Jump to verification steps
	je		VERIFY
	mov		[edi], al
	inc		edi
	mov		al, 42					; Echo * in place of the real character
	call	WriteChar
	jmp		L1
VERIFY:
	call	Crlf
	mov		BYTE PTR [edi], 0		; Null terminate
	INVOKE Str_compare, ADDR buffer, ADDR pass1
	jz		Pass_Good				; Password is correct
									; Password is wrong
	mov		eax, red+(white*16)		; Change text and background colors for the error message
    call	SetTextColor
	mov		edx, OFFSET passBad		
	call	WriteString				; Display the password wrong message
	mov		eax, white+(black*16)
    call	SetTextColor			; Restore the default text and background colors
	jmp		START

Pass_Good:
	mov		eax, green+(white*16)	; Change text and background colors for the error message
    call	SetTextColor
	mov		edx, OFFSET passGood	
	call	WriteString				; Display the password GOOD message
	mov		eax, white+(black*16)
    call	SetTextColor			; Restore the default text and background colors

	mov		esi, passKey
	mov		edi, OFFSET pass1
	mov		ecx, LENGTHOF pass1
	call	Crypt					; Encrypt the password after verification

	ret

VerifyPass ENDP

;-------------------------------------------------------------------------
  GetDetails PROC

; PURPOSE	: Retrieve personal details.
;				DOB is validated to contain 8 numerical characters.
; RECIEVES	: Nothing
; RETURNS	: Nothing
;-------------------------------------------------------------------------
	mov		edx, OFFSET promptFname	; Prompt for first name 
	call	WriteString
	mov		edx, OFFSET fname
	mov		ecx, ( SIZEOF fname - 1 )
	call	ReadString				; Read first name

	mov		edx, OFFSET promptLname	; Prompt for last name
	call	WriteString
	mov		edx, OFFSET lname
	mov		ecx, ( SIZEOF lname -1 )
	call	ReadString				; Read last name

ReadDob:
	call	Crlf
	mov		edx, OFFSET promptDob	; Prompt for DoB
	call	WriteString
	mov		edi, OFFSET dob			; Save buffer address on EDX
	mov		ecx, ( SIZEOF dob -1 )	; Save buffer size on ECX. -1 accounts for the null terminator
L1:	
	cmp		ecx, 8					; Index of the first "/"
	je		WriteSlash				; Jump to automatically adding a "/" 
	cmp		ecx, 5					; Index of the second "/"
	je		WriteSlash				; Jump to automatically adding a "/" 
	call	ReadChar				; Read user input
	cmp		al, 13					; ASCII for ENTER
	je		ReadDob
	cmp		al, 48					; ASCII 0
	jb		L1						; ASCII value too low to be a number. Retry
	cmp		al, 57					; ASCII 9
	ja		L1						; ASCII value too large for a number. Retry
	jmp		Write
WriteSlash:
	mov		al, 47					; AL set to the ASCII value for /
Write:
	call	WriteChar				; ASCII value of a number. Display
	mov		[edi], al				; Save input on buffer index
	inc		edi						; Increment index

	LOOP	L1						; Continue loop until buffer is full
	
	call Crlf
	ret
GetDetails ENDP

;-------------------------------------------------------------------------
Str_concat PROC USES eax ecx esi edi,
	source:PTR BYTE, ; source string
	target:PTR BYTE  ; target string

; PURPOSE	: Concatenates a string at source to the string at target.
; REQUIRES	: The target string must contain enough space to hold both strings.
; RECIEVES	: Pointer to source, Pointer to target
; RETURNS	: Nothing
;-------------------------------------------------------------------------
	INVOKE Str_length, source
	mov		ecx, eax
	mov		esi, source
	mov		edi, target
	INVOKE Str_length, target
	add		edi, eax
	rep		movsb
	ret
Str_concat ENDP

;-------------------------------------------------------------------------
  ClearBuffer PROC

; PURPOSE	: Clear the buffer by replacing all elements with 0
; RECIEVES	: Nothing
; RETURNS	: Nothing
;-------------------------------------------------------------------------
	mov		ecx, bufferMax
	mov		edi, OFFSET buffer
L1:
	mov		BYTE PTR [edi], 0
	inc		edi
	LOOP L1

	ret
ClearBuffer ENDP

;-------------------------------------------------------------------------
  CreateDataString PROC

; PURPOSE	: Create the data string to be written to the file.
;			  Buffer is cleared and data is concatenated to it.
; RECIEVES	: Nothing
; RETURNS	: Nothing
;-------------------------------------------------------------------------
	; Build the data string on the buffer

	; Write the StudentID to buffer
	INVOKE Str_copy, ADDR fileLine1, ADDR buffer		

	INVOKE Str_concat, ADDR fileLine2, ADDR buffer
	INVOKE Str_concat, studentIDString, ADDR buffer
	INVOKE Str_concat, ADDR fileLineSep, ADDR buffer

	INVOKE Str_concat, ADDR fileLine3, ADDR buffer
	INVOKE Str_concat, ADDR fname, ADDR buffer
	INVOKE Str_concat, ADDR fileSpace, ADDR buffer
	INVOKE Str_concat, ADDR lname, ADDR buffer
	INVOKE Str_concat, ADDR fileLineSep, ADDR buffer

	INVOKE Str_concat, ADDR fileLine4, ADDR buffer
	INVOKE Str_concat, ADDR dob, ADDR buffer
	INVOKE Str_concat, ADDR fileLineSep, ADDR buffer

	INVOKE Str_concat, ADDR fileLine5, ADDR buffer
	INVOKE Str_concat, ADDR pass1, ADDR buffer
	INVOKE Str_concat, ADDR fileLineSep, ADDR buffer

	ret
CreateDataString ENDP

;-------------------------------------------------------------------------
  WriteDetails PROC
;
; PURPOSE	: Save details on to a text file called details.txt on current directory
; RECIEVES	: Nothing
; RETURNS	: Nothing
;-------------------------------------------------------------------------
	; Try to open "details.txt" file
	INVOKE CreateFile,
		ADDR filename, GENERIC_WRITE, DO_NOT_SHARE, NULL,
		OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0

	cmp		eax, INVALID_HANDLE_VALUE
	jne		WRITE							; File exists. Jump to writing new data
	mov		eax, green+(black*16)	; Change text and background colors for the message
    call	SetTextColor
	mov		edx, OFFSET fileNotFound
	call	WriteString
	mov		eax, white+(black*16)	; Restore text and background colors
    call	SetTextColor

											; Data file not found. Create new file
	INVOKE CreateFile,
		ADDR filename, GENERIC_WRITE, DO_NOT_SHARE, NULL,
		CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0

WRITE:
	mov		fileHandle, eax					; Preserve fileHandle in EAX

	mov		eax, green+(black*16)			; Change text and background colors for the message
    call	SetTextColor
	mov		edx, OFFSET fileFound
	call	WriteString
	mov		eax, white+(black*16)			; Restore text and background colors
    call	SetTextColor
	
	INVOKE SetFilePointer,fileHandle,0,0,FILE_END	; Move the file pointer to the end of the file

	INVOKE Str_length, ADDR buffer			; Find the length of the data string and store it on EAX
	
	INVOKE WriteFile,						; Append text to the file
	    fileHandle, ADDR buffer, eax,
	    NULL, 0

	INVOKE CloseHandle, fileHandle			; Close file

	ret
WriteDetails ENDP

END main