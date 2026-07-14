.global _start
.global exact_memory_operation
.global tracked_object
.text
_start:
    .inst 0x10000081
exact_memory_operation:
    ldrb w0, [x1, #7]
    mov x8, #93
    svc #0
.balign 16
tracked_object:
    .space 16
