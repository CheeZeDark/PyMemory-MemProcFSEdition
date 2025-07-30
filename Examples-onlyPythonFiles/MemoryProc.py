from memprocfs import Vmm
import struct

class RemoteProcessMemoryEditor:
    def __init__(self, process_name=None, pid=None):
        """
        Initialize memory editor for a remote process
        
        Args:
            process_name: Target process name (e.g., "chrome.exe")
            pid: Target process ID (alternative to process_name)
        """
        self.vmm = Vmm(['-device', 'pmem'])
        self.process = None
        self._original_values = {}
        self._original_protections = {}
        
        # Initialize target process
        if pid:
            self.process = self.vmm.process(pid=pid)
        elif process_name:
            self.process = self.vmm.process(process_name)
        
        if not self.process:
            raise RuntimeError(f"Could not access process {process_name or pid}")

    def get_module_address(self, module_name):
        """Get base address of a module in target process"""
        for module in self.process.modules():
            if module.name.lower() == module_name.lower():
                return module.address
        return None

    def change_protection(self, address, size, new_protection):
        """
        Change memory protection in target process
        
        Args:
            address: Memory address (int or hex string)
            size: Size of region to change
            new_protection: String of flags ('R'W'X' combinations)
        
        Returns:
            bool: True if successful
        """
        try:
            if isinstance(address, str):
                address = int(address, 16)

            # Get current protection
            region = self.process.memory.region(address)
            if not region:
                print(f"No memory region at {hex(address)}")
                return False

            # Store original protection
            self._original_protections[address] = {
                'protection': region.protection,
                'size': size
            }

            # Protection flag mapping
            protection_map = {
                'R': 0x01, 'W': 0x02, 'X': 0x04,
                'RW': 0x01 | 0x02,
                'RX': 0x01 | 0x04,
                'WX': 0x02 | 0x04,
                'RWX': 0x01 | 0x02 | 0x04
            }

            if new_protection not in protection_map:
                print(f"Invalid protection: {new_protection}")
                return False

            # Change protection using MemProcFS
            result = self.process.memory.protect(
                address, 
                size, 
                protection_map[new_protection]
            )

            if result:
                print(f"Changed protection at {hex(address)} to {new_protection}")
            return result

        except Exception as e:
            print(f"Protection change failed: {str(e)}")
            return False

    def write_memory(self, address, value, value_type='bytes'):
        """
        Write to memory in target process
        
        Args:
            address: Memory address (int or hex string)
            value: Value to write
            value_type: Type of value ('bytes', 'int', 'float', etc.)
        """
        try:
            if isinstance(address, str):
                address = int(address, 16)

            # Convert value to bytes
            if value_type == 'bytes':
                data = value
            elif value_type == 'int':
                data = struct.pack('<i', value)
            elif value_type == 'uint':
                data = struct.pack('<I', value)
            elif value_type == 'int64':
                data = struct.pack('<q', value)
            elif value_type == 'float':
                data = struct.pack('<f', value)
            elif value_type == 'double':
                data = struct.pack('<d', value)
            elif value_type == 'string':
                data = value.encode('utf-8') + b'\x00'
            else:
                print(f"Unsupported type: {value_type}")
                return False

            # Backup original value
            self._original_values[address] = {
                'data': self.process.memory.read(address, len(data)),
                'size': len(data)
            }

            # Perform write
            bytes_written = self.process.memory.write(address, data)
            return bytes_written == len(data)

        except Exception as e:
            print(f"Write failed: {str(e)}")
            return False

    def patch_dll_memory(self, dll_name, offset, patch_data):
        """
        Patch memory in a DLL module of the target process
        
        Args:
            dll_name: Name of DLL (e.g., "user32.dll")
            offset: Offset from DLL base address
            patch_data: Bytes to write
            
        Returns:
            bool: True if successful
        """
        # Get DLL base address
        dll_base = self.get_module_address(dll_name)
        if not dll_base:
            print(f"DLL {dll_name} not found in target process")
            return False

        target_address = dll_base + offset
        
        # Change protection to RWX if needed
        if not self.change_protection(target_address, len(patch_data), 'RWX'):
            return False

        # Apply patch
        success = self.write_memory(target_address, patch_data, 'bytes')
        
        # Optional: Restore original protection
        # self.restore_protection(target_address)
        
        return success

    def restore_memory(self, address):
        """Restore original memory content"""
        if address not in self._original_values:
            return False

        original = self._original_values[address]
        return self.process.memory.write(
            address, 
            original['data']
        ) == original['size']

    def restore_protection(self, address):
        """Restore original memory protection"""
        if address not in self._original_protections:
            return False

        original = self._original_protections[address]
        return self.change_protection(
            address,
            original['size'],
            original['protection']
        )

# Example Usage
if __name__ == "__main__":
    try:
        # Initialize editor for target process
        # editor = RemoteProcessMemoryEditor(process_name="chrome.exe")
        editor = RemoteProcessMemoryEditor(pid=1234)  # Alternative using PID
        
        # Example: Patch MessageBoxA in user32.dll of target process
        user32_base = editor.get_module_address("user32.dll")
        print(f"user32.dll base in target process: {hex(user32_base)}")
        
        # Hypothetical MessageBoxA offset (find real offset with reverse engineering)
        msgbox_offset = 0x12345  
        
        # Example patch (NOP first 5 bytes)
        if editor.patch_dll_memory("user32.dll", msgbox_offset, b'\x90\x90\x90\x90\x90'):
            print("Successfully patched user32.dll in target process!")
            
            # Here you would normally trigger the patched function
            
            # Restore original code
            editor.restore_memory(user32_base + msgbox_offset)
            print("Original code restored")
        
    except Exception as e:
        print(f"Error: {str(e)}")