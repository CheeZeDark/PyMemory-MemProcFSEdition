from memprocfs import Vmm
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
import struct
import sys

class MemoryEditor:
    def __init__(self):
        # Initialize MemProcFS with physical device
        self.vmm = Vmm(['-device', 'pmem'])
        
        # Initialize Capstone disassembler (mode will be set later)
        self.cs = None
        self._init_disassembler()
        
        # Current process info
        self.current_pid = None
        self.current_process = None
        self._original_values = {}
        
    def _init_disassembler(self):
        """Initialize Capstone with appropriate architecture mode"""
        # Get system architecture from MemProcFS
        arch = self.vmm.architecture()
        
        if arch == 'x86_64':
            self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        elif arch == 'x86':
            self.cs = Cs(CS_ARCH_X86, CS_MODE_32)
        else:
            raise RuntimeError(f"Unsupported architecture: {arch}")
            
        # Configure disassembler
        self.cs.detail = True
        self.cs.syntax = 0  # CS_OPT_SYNTAX_INTEL

    def _get_process(self, process_name=None, pid=None):
        """Get process handle with fallback to current process"""
        if pid:
            return self.vmm.process(pid=pid)
        elif process_name:
            return self.vmm.process(process_name)
        elif self.current_process:
            return self.current_process
        else:
            self.current_pid = self.vmm.pid()
            self.current_process = self.vmm.process(pid=self.current_pid)
            return self.current_process

    def read_bytes(self, address, size, process_name=None, pid=None):
        """
        Read bytes from memory
        
        Args:
            address: Memory address (int or hex string)
            size: Number of bytes to read
            process_name: Target process name (None for current)
            pid: Target process ID (None for current)
            
        Returns:
            bytes: The read bytes or None if failed
        """
        process = self._get_process(process_name, pid)
        if not process:
            print(f"Process not found")
            return None
            
        try:
            if isinstance(address, str):
                address = int(address, 16)
                
            return process.memory.read(address, size)
        except Exception as e:
            print(f"Read failed at {hex(address)}: {str(e)}")
            return None

    def write_bytes(self, address, data, process_name=None, pid=None):
        """
        Write bytes to memory
        
        Args:
            address: Memory address (int or hex string)
            data: Bytes to write
            process_name: Target process name (None for current)
            pid: Target process ID (None for current)
            
        Returns:
            bool: True if successful
        """
        process = self._get_process(process_name, pid)
        if not process:
            return False
            
        try:
            if isinstance(address, str):
                address = int(address, 16)
                
            # Backup original bytes
            self._original_values[address] = self.read_bytes(address, len(data), process_name, pid)
            
            # Write new bytes
            bytes_written = process.memory.write(address, data)
            return bytes_written == len(data)
        except Exception as e:
            print(f"Write failed at {hex(address)}: {str(e)}")
            return False

    def disassemble(self, address, size, process_name=None, pid=None):
        """
        Disassemble code at memory address
        
        Args:
            address: Memory address (int or hex string)
            size: Number of bytes to disassemble
            process_name: Target process name (None for current)
            pid: Target process ID (None for current)
            
        Returns:
            list: List of disassembled instructions or None if failed
        """
        code = self.read_bytes(address, size, process_name, pid)
        if not code:
            return None
            
        try:
            instructions = []
            for insn in self.cs.disasm(code, address):
                instructions.append({
                    'address': insn.address,
                    'size': insn.size,
                    'bytes': insn.bytes.hex(),
                    'mnemonic': insn.mnemonic,
                    'op_str': insn.op_str
                })
            return instructions
        except Exception as e:
            print(f"Disassembly failed: {str(e)}")
            return None

    def find_and_patch(self, pattern, replacement, process_name=None, pid=None, module_name=None):
        """
        Find pattern in memory and patch it
        
        Args:
            pattern: List of bytes with None for wildcards (e.g., [0x48, 0x8B, None, None])
            replacement: List of bytes to write
            process_name: Target process name
            pid: Target process ID
            module_name: Optional module to limit search
            
        Returns:
            int: Number of patches applied
        """
        process = self._get_process(process_name, pid)
        if not process:
            return 0
            
        # Get target modules
        if module_name:
            modules = [m for m in process.modules() if m.name.lower() == module_name.lower()]
        else:
            modules = process.modules()
            
        if not modules:
            print(f"No modules found")
            return 0
            
        patches_applied = 0
        
        for module in modules:
            print(f"Scanning module: {module.name} ({hex(module.address)}-{hex(module.address + module.size)})")
            
            # Scan module memory in chunks
            chunk_size = 0x10000  # 64KB chunks
            for offset in range(0, module.size, chunk_size - len(pattern)):
                current_address = module.address + offset
                read_size = min(chunk_size, module.size - offset)
                
                data = self.read_bytes(current_address, read_size, process_name, pid)
                if not data:
                    continue
                    
                # Search for pattern
                for i in range(len(data) - len(pattern) + 1):
                    match = True
                    for j in range(len(pattern)):
                        if pattern[j] is not None and data[i+j] != pattern[j]:
                            match = False
                            break
                            
                    if match:
                        patch_address = current_address + i
                        print(f"Found pattern at {hex(patch_address)}")
                        
                        # Apply patch
                        if self.write_bytes(patch_address, bytes(replacement), process_name, pid):
                            print(f"Successfully patched {hex(patch_address)}")
                            patches_applied += 1
                            
        return patches_applied

# Example Usage
if __name__ == "__main__":
    try:
        editor = MemoryEditor()
        
        # Example 1: Read and disassemble code
        print("\n=== Disassembly Example ===")
        target_address = 0x7FF654321000  # Replace with actual address
        instructions = editor.disassemble(target_address, 32)
        if instructions:
            for insn in instructions:
                print(f"{hex(insn['address'])}: {insn['bytes']} \t{insn['mnemonic']} {insn['op_str']}")
        
        # Example 2: Find and patch pattern
        print("\n=== Pattern Patching Example ===")
        # Pattern: MOV instruction with wildcards for registers
        pattern = [0x48, 0x8B, None, None, 0x89, 0x5C, 0x24, None]
        # Replacement: NOP slide
        replacement = [0x90] * 8
        
        patches = editor.find_and_patch(
            pattern, 
            replacement,
            process_name="notepad.exe",
            module_name="ntdll.dll"
        )
        print(f"Applied {patches} patches")
        
        # Example 3: Direct memory read/write
        print("\n=== Direct Memory Access Example ===")
        test_address = 0x7FF654322000  # Replace with actual address
        original = editor.read_bytes(test_address, 4)
        print(f"Original bytes at {hex(test_address)}: {original.hex() if original else 'Failed'}")
        
        if editor.write_bytes(test_address, b'\x90\x90\x90\x90'):
            print("Successfully wrote NOPs")
            modified = editor.read_bytes(test_address, 4)
            print(f"Modified bytes: {modified.hex() if modified else 'Failed'}")
            
            # Restore original
            if test_address in editor._original_values:
                editor.write_bytes(test_address, editor._original_values[test_address])
                print("Original bytes restored")
        
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)