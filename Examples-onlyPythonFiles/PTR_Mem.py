from memprocfs import Vmm
import struct

class PointerChainResolver:
    def __init__(self, process_name=None, pid=None):
        """
        Initialize pointer chain resolver
        
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

    def _read_pointer(self, address):
        """Read a pointer value from memory (auto-detects 32/64-bit)"""
        # Determine pointer size based on process architecture
        ptr_size = 8 if self.process.is64bit() else 4
        
        try:
            data = self.process.memory.read(address, ptr_size)
            if not data or len(data) != ptr_size:
                return None
                
            return struct.unpack('<Q' if ptr_size == 8 else '<I', data)[0]
        except:
            return None

    def resolve_chain(self, base_address, offsets, read_final_value=False):
        """
        Follow a chain of pointers to resolve a final address
        
        Args:
            base_address: Starting address (module base or static address)
            offsets: List of offsets to follow (e.g., [0x10, 0x20, 0x30])
            read_final_value: If True, returns the value at final address
            
        Returns:
            The final memory address or value, or None if failed
        """
        current_ptr = base_address
        
        for i, offset in enumerate(offsets):
            # Add offset to current pointer
            current_addr = current_ptr + offset
            
            # Read next pointer in chain (except for final offset if read_final_value)
            if i < len(offsets) - 1 or not read_final_value:
                current_ptr = self._read_pointer(current_addr)
                if current_ptr is None:
                    print(f"Chain broken at offset {i} (address: {hex(current_addr)})")
                    return None
            else:
                # For final value, read the actual value
                return self._read_pointer(current_addr)
        
        return current_ptr

    def resolve_module_chain(self, module_name, offsets, read_final_value=False):
        """
        Resolve pointer chain starting from a module base address
        
        Args:
            module_name: Name of module to use as base
            offsets: List of offsets to follow
            read_final_value: If True, returns the value at final address
            
        Returns:
            The final memory address or value, or None if failed
        """
        module_base = None
        for module in self.process.modules():
            if module.name.lower() == module_name.lower():
                module_base = module.address
                break
        
        if not module_base:
            print(f"Module {module_name} not found")
            return None
            
        return self.resolve_chain(module_base, offsets, read_final_value)

    def read_chain_value(self, base_address, offsets, value_type='int'):
        """
        Follow pointer chain and read typed value at final address
        
        Args:
            base_address: Starting address
            offsets: List of offsets
            value_type: Type of value to read ('int', 'float', 'bytes', etc.)
            
        Returns:
            The read value or None if failed
        """
        final_addr = self.resolve_chain(base_address, offsets)
        if not final_addr:
            return None
            
        try:
            # Determine size and unpack format based on type
            type_info = {
                'int': (4, '<i'),
                'uint': (4, '<I'),
                'int64': (8, '<q'),
                'uint64': (8, '<Q'),
                'float': (4, '<f'),
                'double': (8, '<d'),
                'ptr': (8 if self.process.is64bit() else 4, '<Q' if self.process.is64bit() else '<I')
            }
            
            if value_type == 'bytes':
                # For raw bytes, just read whatever size was requested
                return self.process.memory.read(final_addr, offsets[-1])
            
            if value_type not in type_info:
                print(f"Unsupported value type: {value_type}")
                return None
                
            size, fmt = type_info[value_type]
            data = self.process.memory.read(final_addr, size)
            if not data or len(data) != size:
                return None
                
            return struct.unpack(fmt, data)[0]
        except Exception as e:
            print(f"Failed to read value: {str(e)}")
            return None

# Example Usage
if __name__ == "__main__":
    try:
        # Initialize resolver
        resolver = PointerChainResolver(process_name="game.exe")
        
        # Example 1: Simple pointer chain
        print("\n=== Simple Pointer Chain ===")
        base = 0x12340000
        offsets = [0x10, 0x20, 0x30]  # base + 0x10 -> ptr + 0x20 -> ptr + 0x30
        final_addr = resolver.resolve_chain(base, offsets)
        print(f"Final address: {hex(final_addr) if final_addr else 'Failed'}")
        
        # Example 2: Module-based chain
        print("\n=== Module-Based Pointer Chain ===")
        module_offsets = [0xABCD0, 0x10, 0x20]
        module_value = resolver.resolve_module_chain(
            "game.dll",
            module_offsets,
            read_final_value=True
        )
        print(f"Final value: {hex(module_value) if module_value else 'Failed'}")
        
        # Example 3: Typed value reading
        print("\n=== Typed Value Reading ===")
        typed_value = resolver.read_chain_value(
            base,
            offsets + [0x0],  # Add final offset 0 to read at final pointer
            value_type='float'
        )
        print(f"Float value: {typed_value if typed_value else 'Failed'}")
        
        # Example 4: Complex game data access
        print("\n=== Game Data Access ===")
        player_entity = resolver.resolve_module_chain(
            "client.dll",
            [0xABCDEF0, 0x10, 0x20]  # client.dll + ABCDEF0 -> ptr + 0x10 -> ptr + 0x20
        )
        
        if player_entity:
            health = resolver.read_chain_value(
                player_entity,
                [0x100],  # player_entity + 0x100 = health
                value_type='int'
            )
            print(f"Player health: {health if health else 'Failed'}")
        
    except Exception as e:
        print(f"Error: {str(e)}")