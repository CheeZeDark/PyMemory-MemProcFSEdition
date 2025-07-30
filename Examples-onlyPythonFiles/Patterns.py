from memprocfs import Vmm
import re
from binascii import unhexlify

class PatternScanner:
    def __init__(self, process_name=None, pid=None):
        """
        Initialize pattern scanner for a process
        
        Args:
            process_name: Target process name (e.g., "chrome.exe")
            pid: Target process ID (alternative to process_name)
        """
        self.vmm = Vmm(['-device', 'pmem'])
        self.process = None
        
        # Initialize target process
        if pid:
            self.process = self.vmm.process(pid=pid)
        elif process_name:
            self.process = self.vmm.process(process_name)
        
        if not self.process:
            raise RuntimeError(f"Could not access process {process_name or pid}")

    def _parse_pattern(self, pattern):
        """
        Convert IDA-style pattern to bytes and mask
        Example: "48 8B ? ? 89 5C 24 ?" -> (bytes, mask)
        """
        pattern = pattern.replace('??', '?')
        hex_parts = pattern.split(' ')
        
        bytes_pattern = []
        mask = []
        
        for part in hex_parts:
            if part == '?':
                bytes_pattern.append(0x00)
                mask.append('?')
            else:
                try:
                    bytes_pattern.append(int(part, 16))
                    mask.append('x')
                except ValueError:
                    raise ValueError(f"Invalid pattern component: {part}")
        
        return bytes(bytes_pattern), ''.join(mask)

    def _pattern_matches(self, data, pattern_bytes, pattern_mask):
        """Check if data matches pattern with mask"""
        if len(data) != len(pattern_bytes):
            return False
            
        for i, (byte, mask) in enumerate(zip(pattern_bytes, pattern_mask)):
            if mask == 'x' and data[i] != byte:
                return False
        return True

    def find_pattern_in_module(self, module_name, pattern, scan_size=0xFFFFFF):
        """
        Scan for pattern in a specific module
        
        Args:
            module_name: Name of module to scan (e.g., "kernel32.dll")
            pattern: IDA-style pattern (e.g., "48 8B ? ? 89 5C 24 ?")
            scan_size: Maximum bytes to scan (default: 16MB)
            
        Returns:
            List of addresses where pattern was found
        """
        module = None
        for mod in self.process.modules():
            if mod.name.lower() == module_name.lower():
                module = mod
                break
        
        if not module:
            raise ValueError(f"Module {module_name} not found in process")
        
        return self.find_pattern_in_region(module.address, module.size, pattern, scan_size)

    def find_pattern_in_region(self, start_address, size, pattern, max_matches=10):
        """
        Scan for pattern in a memory region
        
        Args:
            start_address: Starting address to scan
            size: Size of region to scan
            pattern: IDA-style pattern
            max_matches: Maximum matches to return
            
        Returns:
            List of matching addresses
        """
        pattern_bytes, pattern_mask = self._parse_pattern(pattern)
        pattern_len = len(pattern_bytes)
        chunk_size = 0x10000  # 64KB chunks for efficient scanning
        matches = []
        
        print(f"Scanning {hex(start_address)}-{hex(start_address + size)} for pattern: {pattern}")
        
        for offset in range(0, size, chunk_size - pattern_len):
            # Read memory in chunks with overlap
            read_size = min(chunk_size, size - offset)
            if read_size < pattern_len:
                break
                
            try:
                data = self.process.memory.read(start_address + offset, read_size)
                if not data:
                    continue
                    
                # Search through the chunk
                for i in range(len(data) - pattern_len + 1):
                    if self._pattern_matches(data[i:i+pattern_len], pattern_bytes, pattern_mask):
                        match_addr = start_address + offset + i
                        matches.append(match_addr)
                        print(f"Found match at {hex(match_addr)}")
                        
                        if len(matches) >= max_matches:
                            return matches
            except:
                continue
                
        return matches

    def find_xrefs_to(self, target_address, module_name=None, max_matches=10):
        """
        Find cross-references to an address (like IDA's XREFs)
        
        Args:
            target_address: Address being referenced
            module_name: Optional module to limit search
            max_matches: Maximum references to find
            
        Returns:
            List of instruction addresses that reference target_address
        """
        # This is architecture-specific - example for x64
        # Pattern for CALL/QWORD PTR [RIP+disp32] style references
        disp32 = target_address.to_bytes(4, 'little')
        patterns = [
            b"\xFF\x15" + disp32,  # CALL QWORD PTR [RIP+disp32]
            b"\xFF\x25" + disp32,   # JMP QWORD PTR [RIP+disp32]
        ]
        
        matches = []
        if module_name:
            modules = [m for m in self.process.modules() if m.name.lower() == module_name.lower()]
        else:
            modules = self.process.modules()
        
        for module in modules:
            for pattern in patterns:
                found = self.find_pattern_in_region(
                    module.address, 
                    module.size, 
                    ' '.join(f"{b:02X}" for b in pattern)
                )
                matches.extend(found)
                if len(matches) >= max_matches:
                    return matches[:max_matches]
        
        return matches[:max_matches]

# Example Usage
if __name__ == "__main__":
    try:
        # Initialize scanner
        scanner = PatternScanner(process_name="notepad.exe")
        
        # Example 1: Find pattern in specific module
        print("\n=== Pattern Scan in ntdll.dll ===")
        matches = scanner.find_pattern_in_module(
            "ntdll.dll",
            "48 8B ? ? 89 5C 24 ? 48 8B ? ? 48 8B ? ? 89 44 24 ?"
        )
        print(f"Found {len(matches)} matches: {[hex(m) for m in matches]}")
        
        # Example 2: Find cross-references
        print("\n=== Finding XREFs to MessageBoxA ===")
        user32 = scanner.get_module_address("user32.dll")
        msgbox_offset = 0x12345  # Replace with actual MessageBoxA offset
        xrefs = scanner.find_xrefs_to(user32 + msgbox_offset, "notepad.exe")
        print(f"Found {len(xrefs)} references: {[hex(x) for x in xrefs]}")
        
        # Example 3: Scan specific region
        print("\n=== Custom Region Scan ===")
        base = scanner.get_module_address("kernel32.dll")
        custom_matches = scanner.find_pattern_in_region(
            base + 0x1000,
            0x10000,
            "E8 ? ? ? ? 85 C0 74 ? 48 8B"
        )
        print(f"Found {len(custom_matches)} matches in region")
        
    except Exception as e:
        print(f"Error: {str(e)}")