.code

public retrbx

retrbx PROC
	jmp    QWORD PTR [rbx] 
retrbx ENDP

getgadget PROC
	call next
	next:
	pop rax
	sub rax, 7
	ret
getgadget ENDP

END