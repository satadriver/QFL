


;64位汇编程序模板 (Template)
;声明一个ExitProcess函数
ExitProcess PROTO

.data
	;在这里声明变量

.code 
myAsmTest PROC
	;这里写自己的代码
	
	mov rcx,0
	call ExitProcess
myAsmTest ENDP
END