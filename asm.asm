


;64λ������ģ�� (Template)
;����һ��ExitProcess����
ExitProcess PROTO

.data
	;��������������

.code 
myAsmTest PROC
	;����д�Լ��Ĵ���
	
	mov rcx,0
	call ExitProcess
myAsmTest ENDP
END