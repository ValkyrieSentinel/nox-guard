AS = nasm
ASFLAGS = -f elf64
LD = ld
TARGET = nox-core

all: $(TARGET)

$(TARGET): asm/core.o
	$(LD) asm/core.o -o $(TARGET)

asm/core.o: asm/core.asm
	$(AS) $(ASFLAGS) asm/core.asm -o asm/core.o

test: $(TARGET)
	chmod +x scripts/test_asm.sh
	./scripts/test_asm.sh

clean:
	rm -f asm/*.o $(TARGET) /tmp/nox_bad_elf