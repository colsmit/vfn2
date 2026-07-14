.syntax unified
.global _start
.global exact_memory_operation
.global tracked_object
.text
_start:
    ldr r1, =tracked_object
exact_memory_operation:
    ldrb r0, [r1, #7]
    mov r7, #1
    svc #0
.data
.balign 16
tracked_object:
    .space 16
