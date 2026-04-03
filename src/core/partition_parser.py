
import struct
import logging
from dataclasses import dataclass
from typing import List, Optional

@dataclass
class Partition:
    offset: int
    size: int
    type: str  # 'mbr' or 'gpt'
    index: int

class PartitionTableParser:
    """Parses MBR and GPT partition tables."""
    
    def __init__(self, image_path: str):
        self.image_path = image_path
        self.logger = logging.getLogger(__name__)

    def parse(self) -> List[Partition]:
        """Auto-detect and parse partition table."""
        partitions = []
        try:
            with open(self.image_path, 'rb') as f:
                # Check for GPT (Protective MBR + GPT Header)
                # Read GPT Header at LBA 1 (sector size 512 assumed usually)
                f.seek(512)
                gpt_header = f.read(512)
                if gpt_header[:8] == b'EFI PART':
                    self.logger.info("Found GPT Partition Table")
                    return self.parse_gpt(f, gpt_header)
                
                # Check for MBR (0x55AA at offset 510)
                f.seek(0)
                mbr = f.read(512)
                if mbr[510:512] == b'\x55\xaa':
                    self.logger.info("Found MBR Partition Table")
                    return self.parse_mbr(mbr)
                
        except Exception as e:
            self.logger.error(f"Partition parsing failed: {e}")
            
        return partitions

    def parse_mbr(self, mbr_data: bytes) -> List[Partition]:
        partitions = []
        # 4 partition entries of 16 bytes each, starting at offset 446
        for i in range(4):
            offset = 446 + (i * 16)
            entry = mbr_data[offset:offset+16]
            
            # Status 0x80 = bootable, 0x00 = inactive
            status = entry[0]
            # Type code
            part_type = entry[4]
            # LBA start (sector)
            lba_start = struct.unpack('<I', entry[8:12])[0]
            # Number of sectors
            num_sectors = struct.unpack('<I', entry[12:16])[0]
            
            if part_type != 0 and num_sectors > 0:
                partitions.append(Partition(
                    offset=lba_start * 512,
                    size=num_sectors * 512,
                    type='mbr',
                    index=i+1
                ))
        return partitions

    def parse_gpt(self, f, header_data: bytes) -> List[Partition]:
        partitions = []
        
        # Header format: Signature(8) Revision(4) HeaderSize(4) CRC32(4) Reserved(4) CurrentLBA(8) ...
        # Partition entries starting LBA: offset 72 (8 bytes)
        # Number of partition entries: offset 80 (4 bytes)
        # Size of partition entry: offset 84 (4 bytes)
        
        part_entry_lba = struct.unpack('<Q', header_data[72:80])[0]
        num_entries = struct.unpack('<I', header_data[80:84])[0]
        entry_size = struct.unpack('<I', header_data[84:88])[0]
        
        f.seek(part_entry_lba * 512)
        
        # Read all entries
        data = f.read(num_entries * entry_size)
        
        for i in range(num_entries):
            entry_offset = i * entry_size
            entry = data[entry_offset:entry_offset+entry_size]
            
            # First 16 bytes is Type GUID. If all zero, unused entry.
            type_guid = entry[:16]
            if type_guid == b'\x00' * 16:
                continue
                
            # Unique GUID (16 bytes)
            # First LBA (8 bytes)
            first_lba = struct.unpack('<Q', entry[32:40])[0]
            # Last LBA (8 bytes)
            last_lba = struct.unpack('<Q', entry[40:48])[0]
            
            # Attributes (8 bytes)
            # Name (72 bytes, utf-16le)
            
            if last_lba >= first_lba:
                size_sectors = (last_lba - first_lba) + 1
                partitions.append(Partition(
                    offset=first_lba * 512,
                    size=size_sectors * 512,
                    type='gpt',
                    index=i+1
                ))
                
        return partitions
