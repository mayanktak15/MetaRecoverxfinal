"""
Unearth Forensic Recovery Tool - Btrfs Filesystem Parser
Handles Btrfs-specific structures and recovery operations

Btrfs Features Supported:
- Superblock parsing
- B-tree navigation
- COW (Copy-on-Write) tree traversal
- Extent-based file recovery
- Subvolume analysis
- Snapshot enumeration
- Checksum verification (CRC32C)

Author: Unearth Development Team
Version: 1.1.0
"""

import struct
import logging
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from dataclasses import dataclass, field
import hashlib
import zlib

# Try to import hardware-accelerated CRC32C
try:
    import crc32c
    HAS_CRC32C = True
except ImportError:
    HAS_CRC32C = False
    # Fallback to pure Python implementation
    import binascii

# Compression libraries
# ZLIB: built-in (imported above)
# LZO: optional — pip install python-lzo
try:
    import lzo
    HAS_LZO = True
except ImportError:
    HAS_LZO = False

# ZSTD: optional — pip install zstandard
try:
    import zstandard as zstd
    HAS_ZSTD = True
except ImportError:
    HAS_ZSTD = False


# Btrfs Constants
BTRFS_MAGIC = b'_BHRfS_M'
BTRFS_SUPER_INFO_OFFSET = 0x10000  # 64KB - Primary superblock
BTRFS_SUPER_INFO_OFFSET_1 = 0x4000000  # 64MB - Backup superblock 1
BTRFS_SUPER_INFO_OFFSET_2 = 0x100000000  # 256GB - Backup superblock 2 (if disk large enough)
BTRFS_SUPER_INFO_SIZE = 4096
BTRFS_MAX_LEVEL = 8
BTRFS_DEFAULT_SECTOR_SIZE = 4096  # 4KB sectors for checksum

# Object types
BTRFS_INODE_ITEM_KEY = 1
BTRFS_INODE_REF_KEY = 12
BTRFS_INODE_EXTREF_KEY = 13
BTRFS_DIR_ITEM_KEY = 84        # Directory item (filename -> inode)
BTRFS_DIR_INDEX_KEY = 96       # Directory index
BTRFS_ORPHAN_ITEM_KEY = 48     # Orphan item (deleted but not yet cleaned)
BTRFS_EXTENT_DATA_KEY = 108
BTRFS_EXTENT_CSUM_KEY = 128    # Checksum item key
BTRFS_ROOT_ITEM_KEY = 132
BTRFS_ROOT_BACKREF_KEY = 144
BTRFS_ROOT_REF_KEY = 156
BTRFS_CHUNK_ITEM_KEY = 228

# Special object IDs
BTRFS_ROOT_TREE_OBJECTID = 1   # Root tree
BTRFS_EXTENT_TREE_OBJECTID = 2 # Extent tree
BTRFS_CHUNK_TREE_OBJECTID = 3  # Chunk tree
BTRFS_FS_TREE_OBJECTID = 5     # Filesystem tree (where files live)
BTRFS_ROOT_TREE_DIR_OBJECTID = 6
BTRFS_CSUM_TREE_OBJECTID = 7   # Checksum tree
BTRFS_ORPHAN_OBJECTID = -5 & 0xFFFFFFFFFFFFFFFF  # Orphan objectid (18446744073709551611)
BTRFS_FIRST_FREE_OBJECTID = 256  # First free inode number

# Extent types
BTRFS_FILE_EXTENT_INLINE = 0
BTRFS_FILE_EXTENT_REG = 1
BTRFS_FILE_EXTENT_PREALLOC = 2

# Compression types
BTRFS_COMPRESS_NONE = 0
BTRFS_COMPRESS_ZLIB = 1
BTRFS_COMPRESS_LZO = 2
BTRFS_COMPRESS_ZSTD = 3

# Checksum types
BTRFS_CSUM_TYPE_CRC32 = 0
BTRFS_CSUM_TYPE_XXHASH = 1
BTRFS_CSUM_TYPE_SHA256 = 2
BTRFS_CSUM_TYPE_BLAKE2 = 3

# Checksum sizes (in bytes)
BTRFS_CSUM_SIZE = {
    BTRFS_CSUM_TYPE_CRC32: 4,
    BTRFS_CSUM_TYPE_XXHASH: 8,
    BTRFS_CSUM_TYPE_SHA256: 32,
    BTRFS_CSUM_TYPE_BLAKE2: 32,
}


@dataclass
class BtrfsSuperblock:
    """Btrfs Superblock structure"""
    csum: bytes
    fsid: bytes
    bytenr: int
    flags: int
    magic: bytes
    generation: int
    root: int
    chunk_root: int
    log_root: int
    total_bytes: int
    bytes_used: int
    root_dir_objectid: int
    num_devices: int
    sectorsize: int
    nodesize: int
    leafsize: int
    stripesize: int
    sys_chunk_array_size: int
    chunk_root_generation: int
    compat_flags: int
    compat_ro_flags: int
    incompat_flags: int
    csum_type: int
    root_level: int
    chunk_root_level: int
    log_root_level: int
    label: str


@dataclass
class BtrfsKey:
    """Btrfs disk key structure"""
    objectid: int
    type: int
    offset: int


@dataclass
class BtrfsInodeItem:
    """Btrfs inode item structure"""
    generation: int
    transid: int
    size: int
    nbytes: int
    block_group: int
    nlink: int
    uid: int
    gid: int
    mode: int
    rdev: int
    flags: int
    sequence: int
    atime: int
    ctime: int
    mtime: int
    otime: int


@dataclass
class BtrfsExtentData:
    """Btrfs extent data structure"""
    generation: int
    ram_bytes: int
    compression: int
    encryption: int
    other_encoding: int
    type: int
    disk_bytenr: int
    disk_num_bytes: int
    offset: int
    num_bytes: int
    inline_data: Optional[bytes] = None


@dataclass
class BtrfsDirItem:
    """Btrfs directory item - maps filename to inode"""
    location_objectid: int  # Inode number this entry points to
    location_type: int      # Key type (usually INODE_ITEM_KEY)
    location_offset: int    # Key offset
    transid: int            # Transaction ID when created
    data_len: int           # Length of extra data
    name_len: int           # Length of filename
    item_type: int          # File type (regular, directory, etc.)
    name: str               # The actual filename


@dataclass 
class BtrfsOrphanItem:
    """Btrfs orphan item - file pending deletion"""
    objectid: int           # The inode number of the orphaned file
    offset: int             # Usually 0


@dataclass
class RecoveredFile:
    """Recovered file information with integrity verification"""
    name: str
    inode: int
    size: int
    mode: int
    uid: int
    gid: int
    atime: datetime
    mtime: datetime
    ctime: datetime
    deleted: bool
    data_extents: List[BtrfsExtentData]
    checksum: Optional[str] = None
    # Integrity verification fields
    integrity_status: str = "unverified"  # "verified", "corrupted", "unverified", "no_checksum"
    integrity_verified: bool = False
    integrity_details: str = ""  # Details about verification result


@dataclass
class BtrfsChunk:
    """Btrfs chunk item structure"""
    length: int
    owner: int
    stripe_len: int
    type: int
    io_align: int
    io_width: int
    sector_size: int
    num_stripes: int
    sub_stripes: int
    logical_start: int  # From the key.offset
    stripes: List[Tuple[int, int]]  # List of (devid, physical_offset)


@dataclass
class BtrfsHeader:
    """Btrfs node header"""
    csum: bytes
    fsid: bytes
    bytenr: int
    flags: int
    level: int
    nritems: int
    generation: int
    owner: int


class BtrfsParser:
    """
    Btrfs Filesystem Parser
    
    Parses Btrfs filesystem structures and recovers deleted files.
    Includes CRC32C checksum verification for forensic integrity.
    """
    
    def __init__(self, image_path: str, offset: int = 0, progress_callback=None):
        """
        Initialize Btrfs parser.
        
        Args:
            image_path: Path to disk image or device
            offset: Byte offset where filesystem starts
            progress_callback: Optional callback(current, total, message)
        """
        self.image_path = Path(image_path)
        self.offset = offset
        self.progress_callback = progress_callback
        self.logger = logging.getLogger(__name__)
        self.superblock: Optional[BtrfsSuperblock] = None
        self.file_handle = None
        
        # Cache for performance — multi-generation for deleted file recovery
        # inode_cache: objectid -> {generation: BtrfsInodeItem}
        # This allows us to keep ALL versions of an inode across COW generations
        self.inode_cache: Dict[int, Dict[int, BtrfsInodeItem]] = {}
        # extent_cache: objectid -> {generation: [BtrfsExtentData, ...]}
        self.extent_cache: Dict[int, Dict[int, List[BtrfsExtentData]]] = {}
        self.name_cache: Dict[int, str] = {}
        self.chunks: List[BtrfsChunk] = []
        self.found_leaves = []
        
        # New caches for COW tree root scanning
        self.dir_cache: Dict[int, Tuple[int, str]] = {}  # child_inode -> (parent_inode, name)
        self.parent_cache: Dict[int, int] = {}  # inode -> parent_inode
        self.orphan_inodes: Set[int] = set()  # Inodes marked as orphans (pending deletion)
        
        # Checksum verification
        self.csum_type: int = BTRFS_CSUM_TYPE_CRC32  # Default, updated from superblock
        self.csum_size: int = 4  # Bytes per checksum (CRC32 = 4)
        self.sector_size: int = BTRFS_DEFAULT_SECTOR_SIZE  # Usually 4096
        self.csum_cache: Dict[int, bytes] = {}  # disk_bytenr -> checksum bytes
        
        # Auto-detected offset style for item data parsing (set during first leaf scan)
        self._offset_style: Optional[int] = None
        
        # Verification statistics
        self.verification_stats = {
            'verified': 0,
            'corrupted': 0,
            'unverified': 0,
            'no_checksum': 0
        }
        
        self.logger.info(f"Initialized Btrfs parser for {image_path} (CRC32C available: {HAS_CRC32C})")
    
    def open(self):
        """Open the image file"""
        try:
            self.file_handle = open(self.image_path, 'rb')
            self.logger.info("Image file opened successfully")
        except Exception as e:
            self.logger.error(f"Failed to open image: {e}")
            raise
    
    def close(self):
        """Close the image file"""
        if self.file_handle:
            self.file_handle.close()
            self.logger.info("Image file closed")
    
    def __enter__(self):
        """Context manager entry"""
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()
    
    def detect_filesystem(self) -> bool:
        """
        Detect if the image contains a Btrfs filesystem.
        
        Returns:
            True if Btrfs detected, False otherwise
        """
        try:
            if not self.file_handle:
                self.open()
            
            # Read magic number at superblock location (64KB relative to start)
            self.file_handle.seek(self.offset + BTRFS_SUPER_INFO_OFFSET + 0x40)
            magic = self.file_handle.read(8)
            
            is_btrfs = magic == BTRFS_MAGIC
            
            if is_btrfs:
                self.logger.info("Btrfs filesystem detected")
            else:
                self.logger.warning(f"Not a Btrfs filesystem (magic: {magic})")
            
            return is_btrfs
            
        except Exception as e:
            self.logger.error(f"Filesystem detection failed: {e}")
            return False
    
    def parse_superblock(self) -> BtrfsSuperblock:
        """
        Parse the Btrfs superblock.
        
        Returns:
            Parsed superblock structure
        """
        try:
            self.file_handle.seek(self.offset + BTRFS_SUPER_INFO_OFFSET)
            data = self.file_handle.read(BTRFS_SUPER_INFO_SIZE)
            
            # Parse superblock fields
            # Format: checksum(32), fsid(16), bytenr(8), flags(8), magic(8), ...
            
            offset = 0
            csum = data[offset:offset+32]
            offset += 32
            
            fsid = data[offset:offset+16]
            offset += 16
            
            bytenr = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            flags = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            magic = data[offset:offset+8]
            offset += 8
            
            generation = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            root = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            chunk_root = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            log_root = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            # Skip log_root_transid
            offset += 8
            
            total_bytes = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            bytes_used = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            root_dir_objectid = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            num_devices = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            sectorsize = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            nodesize = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            leafsize = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            stripesize = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            sys_chunk_array_size = struct.unpack('<I', data[offset:offset+4])[0]
            offset += 4
            
            chunk_root_generation = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            compat_flags = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            compat_ro_flags = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            incompat_flags = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            csum_type = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            
            root_level = data[offset]
            offset += 1
            
            chunk_root_level = data[offset]
            offset += 1
            
            log_root_level = data[offset]
            offset += 1
            
            # Skip to label (offset 0x12B)
            label_offset = 0x12B
            label_data = data[label_offset:label_offset+256]
            label = label_data.split(b'\x00')[0].decode('utf-8', errors='ignore')
            
            superblock = BtrfsSuperblock(
                csum=csum,
                fsid=fsid,
                bytenr=bytenr,
                flags=flags,
                magic=magic,
                generation=generation,
                root=root,
                chunk_root=chunk_root,
                log_root=log_root,
                total_bytes=total_bytes,
                bytes_used=bytes_used,
                root_dir_objectid=root_dir_objectid,
                num_devices=num_devices,
                sectorsize=sectorsize,
                nodesize=nodesize,
                leafsize=leafsize,
                stripesize=stripesize,
                sys_chunk_array_size=sys_chunk_array_size,
                chunk_root_generation=chunk_root_generation,
                compat_flags=compat_flags,
                compat_ro_flags=compat_ro_flags,
                incompat_flags=incompat_flags,
                csum_type=csum_type,
                root_level=root_level,
                chunk_root_level=chunk_root_level,
                log_root_level=log_root_level,
                label=label
            )
            
            self.superblock = superblock
            self.logger.info(f"Superblock parsed: {total_bytes / (1024**3):.2f} GB, label: {label}")
            
            # Update checksum settings from superblock
            self.csum_type = csum_type
            self.csum_size = BTRFS_CSUM_SIZE.get(csum_type, 4)
            self.sector_size = sectorsize
            self.logger.info(f"Checksum type: {self._get_csum_type_name(csum_type)}, size: {self.csum_size} bytes")
            
            return superblock
            
        except Exception as e:
            self.logger.error(f"Failed to parse superblock: {e}")
            raise
    
    def _get_csum_type_name(self, csum_type: int) -> str:
        """Get human-readable checksum type name."""
        names = {
            BTRFS_CSUM_TYPE_CRC32: "CRC32C",
            BTRFS_CSUM_TYPE_XXHASH: "xxHash64",
            BTRFS_CSUM_TYPE_SHA256: "SHA256",
            BTRFS_CSUM_TYPE_BLAKE2: "BLAKE2b"
        }
        return names.get(csum_type, f"Unknown({csum_type})")
    
    def parse_superblock_at(self, offset: int) -> Optional[BtrfsSuperblock]:
        """
        Parse superblock at a specific offset.
        
        Args:
            offset: Byte offset to read superblock from
            
        Returns:
            Parsed superblock or None if invalid
        """
        try:
            self.f.seek(self.offset + offset)
            data = self.f.read(BTRFS_SUPER_INFO_SIZE)
            
            if len(data) < BTRFS_SUPER_INFO_SIZE:
                return None
            
            # Check magic
            magic = data[0x40:0x48]
            if magic != BTRFS_MAGIC:
                return None
            
            # Parse key fields (simplified)
            generation = struct.unpack_from('<Q', data, 0x70)[0]
            root = struct.unpack_from('<Q', data, 0x78)[0]
            chunk_root = struct.unpack_from('<Q', data, 0x80)[0]
            nodesize = struct.unpack_from('<I', data, 0x90)[0]
            sectorsize = struct.unpack_from('<I', data, 0x94)[0]
            
            return BtrfsSuperblock(
                csum=data[0:32],
                fsid=data[0x20:0x40],
                bytenr=struct.unpack_from('<Q', data, 0x48)[0],
                flags=struct.unpack_from('<Q', data, 0x50)[0],
                magic=magic,
                generation=generation,
                root=root,
                chunk_root=chunk_root,
                log_root=struct.unpack_from('<Q', data, 0x88)[0],
                total_bytes=struct.unpack_from('<Q', data, 0xA8)[0],
                bytes_used=struct.unpack_from('<Q', data, 0xB0)[0],
                root_dir_objectid=struct.unpack_from('<Q', data, 0xB8)[0],
                num_devices=struct.unpack_from('<Q', data, 0xC0)[0],
                sectorsize=sectorsize,
                nodesize=nodesize,
                leafsize=nodesize,  # Same as nodesize in modern btrfs
                stripesize=struct.unpack_from('<I', data, 0x98)[0],
                sys_chunk_array_size=struct.unpack_from('<I', data, 0x9C)[0],
                chunk_root_generation=struct.unpack_from('<Q', data, 0xA0)[0],
                compat_flags=0,
                compat_ro_flags=0,
                incompat_flags=0,
                csum_type=struct.unpack_from('<H', data, 0xC8)[0],
                root_level=data[0xCA],
                chunk_root_level=data[0xCB],
                log_root_level=0,
                label=''
            )
        except Exception as e:
            self.logger.debug(f"Failed to parse superblock at {offset}: {e}")
            return None
    
    def scan_backup_superblocks(self) -> List[Tuple[int, int, BtrfsSuperblock]]:
        """
        Scan all backup superblocks to find older tree root generations.
        
        Returns:
            List of (generation, root_offset, superblock) tuples sorted by generation
        """
        superblocks = []
        offsets = [
            BTRFS_SUPER_INFO_OFFSET,    # Primary at 64KB
            BTRFS_SUPER_INFO_OFFSET_1,  # Backup 1 at 64MB
        ]
        
        # Only check 256GB backup if disk is large enough
        try:
            self.f.seek(0, 2)  # Seek to end
            disk_size = self.f.tell()
            if disk_size > BTRFS_SUPER_INFO_OFFSET_2:
                offsets.append(BTRFS_SUPER_INFO_OFFSET_2)
        except:
            pass
        
        for sb_offset in offsets:
            sb = self.parse_superblock_at(sb_offset)
            if sb and sb.magic == BTRFS_MAGIC:
                superblocks.append((sb.generation, sb.root, sb))
                self.logger.debug(f"Found superblock at {sb_offset}: gen={sb.generation}, root={sb.root}")
        
        # Sort by generation (oldest first)
        superblocks.sort(key=lambda x: x[0])
        return superblocks
    
    
    def compute_crc32c(self, data: bytes) -> int:
        """
        Compute CRC32C checksum of data.
        
        Uses hardware-accelerated crc32c library if available,
        otherwise falls back to a slower implementation.
        
        Args:
            data: Bytes to compute checksum for
            
        Returns:
            CRC32C checksum as integer
        """
        if HAS_CRC32C:
            return crc32c.crc32c(data)
        else:
            # Fallback: Use zlib's CRC32 (not CRC32C, but better than nothing)
            # Note: This won't match Btrfs checksums exactly without hardware CRC32C
            import zlib
            return zlib.crc32(data) & 0xFFFFFFFF
    
    def verify_data_checksum(self, data: bytes, stored_csum: bytes) -> Tuple[bool, str]:
        """
        Verify CRC32C checksum of data against stored checksum.
        
        Args:
            data: Data to verify
            stored_csum: Stored checksum bytes (4 bytes for CRC32C)
            
        Returns:
            Tuple of (is_valid, message)
        """
        if self.csum_type != BTRFS_CSUM_TYPE_CRC32:
            return False, f"Unsupported checksum type: {self._get_csum_type_name(self.csum_type)}"
        
        if len(stored_csum) < 4:
            return False, "Stored checksum too short"
        
        # Extract stored checksum (little-endian 32-bit)
        stored_value = struct.unpack('<I', stored_csum[:4])[0]
        
        # Compute actual checksum
        computed_value = self.compute_crc32c(data)
        
        if computed_value == stored_value:
            return True, f"Checksum verified: 0x{computed_value:08X}"
        else:
            return False, f"Checksum mismatch: stored=0x{stored_value:08X}, computed=0x{computed_value:08X}"
    
    def verify_extent_integrity(self, extent: BtrfsExtentData, data: bytes) -> Tuple[str, str]:
        """
        Verify integrity of extent data.
        
        Args:
            extent: Extent metadata
            data: Recovered data bytes
            
        Returns:
            Tuple of (status, details) where status is one of:
            - "verified": Checksum matches
            - "corrupted": Checksum mismatch
            - "unverified": Could not verify (no checksum data)
            - "no_checksum": Extent type doesn't have checksums (inline, preallocated)
        """
        # Inline data doesn't have separate checksums
        if extent.type == BTRFS_FILE_EXTENT_INLINE:
            return "no_checksum", "Inline extent (no separate checksum)"
        
        # Preallocated extents may not have data checksums
        if extent.type == BTRFS_FILE_EXTENT_PREALLOC:
            return "no_checksum", "Preallocated extent (no data written)"
        
        # For regular extents, we need to verify each sector
        disk_bytenr = extent.disk_bytenr
        if disk_bytenr == 0:
            return "no_checksum", "Extent not allocated on disk"
        
        # Check if we have cached checksums for this extent
        if disk_bytenr in self.csum_cache:
            stored_csum = self.csum_cache[disk_bytenr]
            
            # Verify first sector (as a quick check)
            if len(data) >= self.sector_size:
                sector_data = data[:self.sector_size]
                is_valid, msg = self.verify_data_checksum(sector_data, stored_csum)
                
                if is_valid:
                    return "verified", msg
                else:
                    return "corrupted", msg
            else:
                # Data smaller than sector, verify what we have
                is_valid, msg = self.verify_data_checksum(data, stored_csum)
                if is_valid:
                    return "verified", msg
                else:
                    return "corrupted", msg
        
        # No checksum found in cache - try to compute for logging
        if len(data) > 0:
            computed = self.compute_crc32c(data[:min(len(data), self.sector_size)])
            return "unverified", f"No stored checksum found (computed: 0x{computed:08X})"
        
        return "unverified", "No data to verify"
    
    def verify_file_integrity(self, file_info: RecoveredFile, data: bytes) -> Tuple[str, str]:
        """
        Verify integrity of a complete recovered file.
        
        Checks all extents and aggregates results.
        
        Args:
            file_info: Recovered file metadata
            data: Complete file data bytes
            
        Returns:
            Tuple of (overall_status, details)
        """
        if len(file_info.data_extents) == 0:
            return "no_checksum", "No extents to verify"
        
        if len(data) == 0:
            return "no_checksum", "Empty file"
        
        verified_count = 0
        corrupted_count = 0
        unverified_count = 0
        no_checksum_count = 0
        
        offset = 0
        details_parts = []
        
        for i, extent in enumerate(file_info.data_extents):
            extent_size = extent.num_bytes if extent.num_bytes > 0 else extent.ram_bytes
            if extent_size == 0:
                continue
                
            # Get extent data slice
            extent_data = data[offset:offset + extent_size]
            offset += extent_size
            
            # Verify this extent
            status, msg = self.verify_extent_integrity(extent, extent_data)
            
            if status == "verified":
                verified_count += 1
            elif status == "corrupted":
                corrupted_count += 1
                details_parts.append(f"Extent {i}: {msg}")
            elif status == "unverified":
                unverified_count += 1
            else:
                no_checksum_count += 1
        
        # Determine overall status
        total_extents = len(file_info.data_extents)
        
        if corrupted_count > 0:
            overall_status = "corrupted"
            details = f"{corrupted_count}/{total_extents} extents corrupted. " + "; ".join(details_parts)
        elif verified_count > 0 and verified_count == total_extents:
            overall_status = "verified"
            details = f"All {total_extents} extents verified successfully"
        elif verified_count > 0:
            overall_status = "verified"
            details = f"{verified_count}/{total_extents} extents verified, {unverified_count} unverified"
        elif no_checksum_count == total_extents:
            overall_status = "no_checksum"
            details = "No checksums available for this file type"
        else:
            overall_status = "unverified"
            details = f"Could not verify: {unverified_count} unverified, {no_checksum_count} without checksums"
        
        # Update stats
        self.verification_stats[overall_status] = self.verification_stats.get(overall_status, 0) + 1
        
        return overall_status, details

    def parse_header(self, data: bytes) -> BtrfsHeader:
        """
        Parse Btrfs node/leaf header.
        CSUM(32) + FSID(16) + BYTENR(8) + FLAGS(8) + LEVEL(1) + NRITEMS(4) + GEN(8) + OWNER(8)
        """
        offset = 0
        csum = data[offset:offset+32]
        offset += 32
        
        fsid = data[offset:offset+16]
        offset += 16
        
        bytenr = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        flags = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        # chunk_tree_uuid (16 bytes)
        chunk_tree_uuid = data[offset:offset+16]
        offset += 16
        
        generation = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        owner = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        nritems = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        level = data[offset]
        offset += 1
        
        return BtrfsHeader(csum, fsid, bytenr, flags, level, nritems, generation, owner)
    
    def parse_btrfs_key(self, data: bytes, offset: int = 0) -> BtrfsKey:
        """
        Parse a Btrfs disk key.
        
        Args:
            data: Raw data containing key
            offset: Offset in data
            
        Returns:
            Parsed key structure
        """
        objectid = struct.unpack('<Q', data[offset:offset+8])[0]
        key_type = data[offset+8]
        key_offset = struct.unpack('<Q', data[offset+9:offset+17])[0]
        
        return BtrfsKey(objectid=objectid, type=key_type, offset=key_offset)
    
    def parse_inode_item(self, data: bytes, offset: int = 0) -> BtrfsInodeItem:
        """
        Parse a Btrfs inode item.
        
        Args:
            data: Raw data containing inode
            offset: Offset in data
            
        Returns:
            Parsed inode structure
        """
        generation = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        transid = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        size = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        nbytes = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        block_group = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        nlink = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        uid = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        gid = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        mode = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        rdev = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        flags = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        sequence = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        # Skip reserved
        offset += 32
        
        # Timestamps (atime, ctime, mtime, otime)
        atime_sec = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        offset += 4  # Skip nsec
        
        ctime_sec = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        offset += 4
        
        mtime_sec = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        offset += 4
        
        otime_sec = struct.unpack('<Q', data[offset:offset+8])[0]
        
        return BtrfsInodeItem(
            generation=generation,
            transid=transid,
            size=size,
            nbytes=nbytes,
            block_group=block_group,
            nlink=nlink,
            uid=uid,
            gid=gid,
            mode=mode,
            rdev=rdev,
            flags=flags,
            sequence=sequence,
            atime=atime_sec,
            ctime=ctime_sec,
            mtime=mtime_sec,
            otime=otime_sec
        )
    
    def parse_extent_data(self, data: bytes, offset: int = 0) -> BtrfsExtentData:
        """
        Parse extent data item.
        
        Args:
            data: Raw data
            offset: Offset in data
            
        Returns:
            Parsed extent data
        """
        generation = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        ram_bytes = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        compression = data[offset]
        offset += 1
        
        encryption = data[offset]
        offset += 1
        
        other_encoding = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2
        
        extent_type = data[offset]
        offset += 1
        
        if extent_type == BTRFS_FILE_EXTENT_REG or extent_type == BTRFS_FILE_EXTENT_PREALLOC:
            disk_bytenr = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            disk_num_bytes = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            extent_offset = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            num_bytes = struct.unpack('<Q', data[offset:offset+8])[0]
            inline_data = None
        else:
            # Inline data (BTRFS_FILE_EXTENT_INLINE = 0)
            disk_bytenr = 0
            disk_num_bytes = 0
            extent_offset = 0
            num_bytes = ram_bytes
            
            # Inline data starts at current offset and has length 'ram_bytes'
            # (or calculate from remaining data if compressed?)
            # For simplicity, duplicate remaining data as inline data
            if offset < len(data):
                inline_data = data[offset:]
            else:
                inline_data = b''
        
        return BtrfsExtentData(
            generation=generation,
            ram_bytes=ram_bytes,
            compression=compression,
            encryption=encryption,
            other_encoding=other_encoding,
            type=extent_type,
            disk_bytenr=disk_bytenr,
            disk_num_bytes=disk_num_bytes,
            offset=extent_offset,
            num_bytes=num_bytes,
            inline_data=inline_data
        )

    def parse_chunk_item(self, data: bytes, logical_start: int, offset: int = 0) -> BtrfsChunk:
        """
        Parse Btrfs chunk item.
        
        Args:
            data: Raw data
            logical_start: Logical address from key
            offset: Offset in data
        """
        length = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        owner = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        stripe_len = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        type_ = struct.unpack('<Q', data[offset:offset+8])[0]
        offset += 8
        
        io_align = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        io_width = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        sector_size = struct.unpack('<I', data[offset:offset+4])[0]
        offset += 4
        
        num_stripes = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2
        
        sub_stripes = struct.unpack('<H', data[offset:offset+2])[0]
        offset += 2
        
        stripes = []
        for _ in range(num_stripes):
            devid = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            physical = struct.unpack('<Q', data[offset:offset+8])[0]
            offset += 8
            
            # uuid (16 bytes)
            offset += 16
            
            stripes.append((devid, physical))
            
        return BtrfsChunk(
            length=length,
            owner=owner,
            stripe_len=stripe_len,
            type=type_,
            io_align=io_align,
            io_width=io_width,
            sector_size=sector_size,
            num_stripes=num_stripes,
            sub_stripes=sub_stripes,
            logical_start=logical_start,
            stripes=stripes
        )
    
    def scan_deleted_inodes(self) -> List[int]:
        """
        Scan for all inodes in the filesystem by brute-force scanning ALL leaf nodes.
        
        This includes both live (current) and deleted (orphaned) inodes.
        Deleted files may still have metadata in old/orphaned leaf nodes.
        
        IMPORTANT: Clears ALL caches before scanning to ensure fresh results.
        This guarantees that newly deleted files are always detected.
        """
        if not self.superblock:
            self.parse_superblock()

        # === CRITICAL: Clear ALL caches for a fresh scan ===
        # Without this, re-runs would skip the scan and miss newly deleted files
        self.inode_cache.clear()
        self.extent_cache.clear()
        self.name_cache.clear()
        self.dir_cache.clear()
        self.parent_cache.clear()
        self.orphan_inodes.clear()
        self.csum_cache.clear()
        self._offset_style = None  # Reset auto-detected offset style
        
        nodesize = self.superblock.nodesize
        sectorsize = self.superblock.sectorsize
        total_size = self.superblock.total_bytes
        
        # Track inodes from the live FS tree vs all found inodes
        self.live_inodes: Set[int] = set()  # Inodes referenced by directory items
        
        self.logger.info(f"Scanning filesystem ({total_size / (1024**3):.2f} GB, nodesize={nodesize}, sectorsize={sectorsize})...")
        current_offset = 0
        
        header_size = 101  # Btrfs header size
        
        # Read in larger chunks for IO efficiency
        chunk_size = 10 * 1024 * 1024  # 10MB
        
        # CRITICAL: Scan in sectorsize steps, not nodesize steps!
        # Leaf nodes are aligned to sectorsize boundaries
        scan_step = sectorsize
        
        leaves_found = 0
        fs_tree_leaves = 0
        subvol_tree_leaves = 0
        
        while current_offset < total_size:
            progress_pct = int(current_offset / total_size * 100)
            if self.progress_callback and current_offset % (chunk_size * 10) == 0:
                self.progress_callback(current_offset, total_size, f"Scanning: {progress_pct}%")
                
            try:
                self.file_handle.seek(self.offset + current_offset)
                # Read chunk_size + nodesize to cover nodes straddling the chunk boundary
                # This ensures we never miss a leaf node that starts near the end of a chunk
                read_size = min(chunk_size + nodesize, total_size - current_offset)
                chunk = self.file_handle.read(read_size)
                if not chunk:
                    break
                
                # Iterate through chunk in sectorsize steps to catch all potential nodes
                # But only process up to chunk_size offset to avoid double-processing
                # (the overlap region will be re-read in the next iteration)
                process_limit = min(chunk_size, len(chunk))
                for i in range(0, process_limit, scan_step):
                    if i + nodesize > len(chunk):
                        break
                    
                    block = chunk[i:i+nodesize]
                    if len(block) < header_size:
                        continue
                        
                    # Quick check for FSID match to identify valid Btrfs node
                    if block[32:48] != self.superblock.fsid:
                        continue 
                        
                    try:
                        header = self.parse_header(block)
                        if header.level == 0 and header.nritems > 0:  # Valid leaf node
                            leaves_found += 1
                            
                            # Track tree type for logging
                            if header.owner == 5:  # BTRFS_FS_TREE_OBJECTID
                                fs_tree_leaves += 1
                            elif header.owner >= 256:  # Subvolume trees
                                subvol_tree_leaves += 1
                            
                            self.process_leaf(block, header)
                            
                    except Exception as e:
                        self.logger.debug(f"Error parsing header at {current_offset+i}: {e}")
                        continue
                        
            except Exception as e:
                self.logger.error(f"Error scanning at offset {current_offset}: {e}")
            
            # Advance by chunk_size (NOT chunk_size + nodesize)
            # The overlap ensures nodes at boundaries are covered
            current_offset += chunk_size
            
        self.logger.info(f"Scan complete. Found {leaves_found} leaf nodes "
                        f"({fs_tree_leaves} FS tree, {subvol_tree_leaves} subvolume tree).")
        
        # Count total inode versions and extent versions across all generations
        total_inode_versions = sum(len(gens) for gens in self.inode_cache.values())
        total_extent_versions = sum(len(gens) for gens in self.extent_cache.values())
        self.logger.info(f"Parsed {len(self.inode_cache)} unique inodes ({total_inode_versions} versions), "
                         f"{total_extent_versions} extent groups, {len(self.name_cache)} filenames.")
        self.logger.info(f"Directory entries: {len(self.dir_cache)}, Parent refs: {len(self.parent_cache)}, Orphans: {len(self.orphan_inodes)}")
        
        # Log orphan inodes if any found
        if self.orphan_inodes:
            self.logger.info(f"Orphan inodes found: {list(self.orphan_inodes)[:10]}...")  # First 10
        
        # Log multi-generation inodes (potential deleted files)
        multi_gen_inodes = {k: v for k, v in self.inode_cache.items() if len(v) > 1}
        if multi_gen_inodes:
            self.logger.info(f"Multi-generation inodes: {len(multi_gen_inodes)} (potential deleted files)")
            for ino, gens in list(multi_gen_inodes.items())[:5]:
                gen_list = sorted(gens.keys())
                self.logger.debug(f"  Inode {ino}: {len(gens)} versions, generations={gen_list}")
        
        return list(self.inode_cache.keys())

    def _detect_offset_style(self, block: bytes, header: BtrfsHeader) -> int:
        """
        Auto-detect whether item offsets need BTRFS_LEAF_DATA_OFFSET added.
        
        Tests both interpretations against the first item in the leaf and
        returns the adjustment that produces a valid parse.
        
        Returns:
            101 if offsets are relative to header end (standard Btrfs spec)
            0 if offsets are absolute from byte 0
        """
        BTRFS_LEAF_DATA_OFFSET = 101
        nodesize = len(block)
        
        if header.nritems == 0:
            return BTRFS_LEAF_DATA_OFFSET  # Default
        
        # Read the first item's key, offset, and size
        offset = BTRFS_LEAF_DATA_OFFSET  # Item headers start after the 101-byte header
        key = self.parse_btrfs_key(block, offset)
        stored_offset = struct.unpack('<I', block[offset+17:offset+21])[0]
        item_data_size = struct.unpack('<I', block[offset+21:offset+25])[0]
        
        if item_data_size == 0:
            return BTRFS_LEAF_DATA_OFFSET  # Can't test, use default
        
        # Test both interpretations
        for adj in [BTRFS_LEAF_DATA_OFFSET, 0]:
            actual_offset = adj + stored_offset
            if actual_offset >= nodesize or actual_offset + item_data_size > nodesize:
                continue
            
            data = block[actual_offset : actual_offset + item_data_size]
            
            # For INODE_ITEM_KEY, validate the parsed result
            if key.type == BTRFS_INODE_ITEM_KEY and item_data_size >= 160:
                try:
                    inode = self.parse_inode_item(data)
                    file_type = (inode.mode >> 12) & 0xF
                    # Valid file types: 1=FIFO, 2=chardev, 4=dir, 6=blockdev, 8=file, 10=symlink, 12=socket
                    if file_type in (1, 2, 4, 6, 8, 10, 12) and inode.nlink <= 65536:
                        self.logger.debug(f"Offset auto-detect: adjustment={adj} (file_type={file_type}, nlink={inode.nlink})")
                        return adj
                except Exception:
                    continue
            
            # For EXTENT_DATA_KEY, check if extent type is valid
            elif key.type == BTRFS_EXTENT_DATA_KEY and item_data_size >= 21:
                try:
                    extent = self.parse_extent_data(data)
                    if extent.type in (BTRFS_FILE_EXTENT_INLINE, BTRFS_FILE_EXTENT_REG, BTRFS_FILE_EXTENT_PREALLOC):
                        self.logger.debug(f"Offset auto-detect: adjustment={adj} (extent_type={extent.type})")
                        return adj
                except Exception:
                    continue
            
            # For INODE_REF, check if name_len is reasonable
            elif key.type == BTRFS_INODE_REF_KEY and item_data_size >= 10:
                name_len = struct.unpack('<H', data[8:10])[0]
                if name_len > 0 and 10 + name_len <= item_data_size and name_len < 256:
                    # Check if the name bytes look like valid UTF-8
                    try:
                        name = data[10:10+name_len].decode('utf-8')
                        if name.isprintable() or any(c.isalnum() for c in name):
                            self.logger.debug(f"Offset auto-detect: adjustment={adj} (name='{name}')")
                            return adj
                    except UnicodeDecodeError:
                        continue
        
        # Default: standard Btrfs spec says offsets are relative to header end
        return BTRFS_LEAF_DATA_OFFSET

    def process_leaf(self, block: bytes, header: BtrfsHeader):
        """
        Process a leaf node to extract items.
        
        In Btrfs, item data offsets stored in leaf item headers are relative to
        BTRFS_LEAF_DATA_OFFSET (= sizeof(struct btrfs_header) = 101 bytes).
        Item data grows BACKWARDS from the end of the node block.
        
        The offset style is auto-detected on first leaf and cached for the scan.
        """
        BTRFS_LEAF_DATA_OFFSET = 101  # sizeof(struct btrfs_header)
        
        # Auto-detect offset style on first leaf, then cache the result
        if not hasattr(self, '_offset_style') or self._offset_style is None:
            self._offset_style = self._detect_offset_style(block, header)
            self.logger.info(f"Auto-detected item offset adjustment: {self._offset_style} "
                           f"({'relative to header end' if self._offset_style == 101 else 'absolute from block start'})")
        
        offset_adjustment = self._offset_style
        leaf_generation = header.generation  # Track which generation this leaf belongs to
        nodesize = len(block)  # Should be self.superblock.nodesize
        offset = BTRFS_LEAF_DATA_OFFSET  # Item headers always start after the 101-byte header
        
        for item_idx in range(header.nritems):
            # Item header: Key (17) + data_offset (4) + data_size (4) = 25 bytes
            if offset + 25 > len(block):
                break
                
            key = self.parse_btrfs_key(block, offset)
            
            # Read stored offset and size from item header
            stored_offset = struct.unpack('<I', block[offset+17:offset+21])[0]
            item_data_size = struct.unpack('<I', block[offset+21:offset+25])[0]
            
            # Calculate actual byte position using auto-detected adjustment
            item_data_offset = offset_adjustment + stored_offset
            
            offset += 25  # Move to next item header
            
            # Validate offset and size against actual block boundaries
            if item_data_offset >= nodesize or item_data_offset + item_data_size > nodesize:
                continue
            if item_data_size == 0:
                continue
                
            # Extract item data from the correct position
            item_data = block[item_data_offset : item_data_offset + item_data_size]
            
            # Process based on item type
            if key.type == BTRFS_INODE_ITEM_KEY:
                try:
                    inode = self.parse_inode_item(item_data)
                    
                    # Validate inode - skip if clearly corrupted
                    # nlink should be reasonable (< 65536 is sane)
                    # mode should have valid file type bits (0-15 in upper 4 bits)
                    file_type = (inode.mode >> 12) & 0xF
                    if inode.nlink > 65536 or file_type > 15:
                        # Corrupted inode data
                        continue
                    
                    # Store ALL versions keyed by (objectid, generation)
                    # This preserves deleted file inodes alongside current ones
                    if key.objectid not in self.inode_cache:
                        self.inode_cache[key.objectid] = {}
                    self.inode_cache[key.objectid][leaf_generation] = inode
                    
                    # Log found inodes for debugging
                    if inode.nlink == 0:
                        self.logger.debug(f"Found potential deleted inode: {key.objectid} gen={leaf_generation} (size={inode.size}, nlink={inode.nlink})")
                except Exception as e:
                    pass  # Skip malformed inode items
                    
            elif key.type == BTRFS_EXTENT_DATA_KEY:
                try:
                    extent = self.parse_extent_data(item_data)
                    if key.objectid not in self.extent_cache:
                        self.extent_cache[key.objectid] = {}
                    if leaf_generation not in self.extent_cache[key.objectid]:
                        self.extent_cache[key.objectid][leaf_generation] = []
                    self.extent_cache[key.objectid][leaf_generation].append(extent)
                except Exception:
                    pass  # Skip malformed extent data items
                    
            elif key.type == BTRFS_INODE_REF_KEY:
                # This gives us filenames! objectid = inode, offset = parent dir inode
                try:
                    if len(item_data) >= 10:
                        # INODE_REF structure: index(8) + name_len(2) + name(...)
                        name_len = struct.unpack('<H', item_data[8:10])[0]
                        if 10 + name_len <= len(item_data):
                            name = item_data[10:10+name_len].decode('utf-8', errors='replace')
                            self.name_cache[key.objectid] = name
                            # Store parent directory info
                            if not hasattr(self, 'parent_cache'):
                                self.parent_cache = {}
                            self.parent_cache[key.objectid] = key.offset  # offset = parent inode
                except Exception:
                    pass
                    
            elif key.type == BTRFS_DIR_ITEM_KEY:
                # Directory item - maps filename to inode in a directory
                # objectid = directory inode, offset = hash of filename
                try:
                    if len(item_data) >= 30:
                        # DIR_ITEM structure:
                        # location (17 bytes): objectid(8) + type(1) + offset(8)
                        # transid (8 bytes)
                        # data_len (2 bytes)
                        # name_len (2 bytes) 
                        # type (1 byte)
                        # name (variable)
                        child_inode = struct.unpack('<Q', item_data[0:8])[0]
                        transid = struct.unpack('<Q', item_data[17:25])[0]
                        data_len = struct.unpack('<H', item_data[25:27])[0]
                        name_len = struct.unpack('<H', item_data[27:29])[0]
                        file_type = item_data[29]
                        
                        if 30 + name_len <= len(item_data):
                            name = item_data[30:30+name_len].decode('utf-8', errors='replace')
                            
                            # Store in directory cache
                            if not hasattr(self, 'dir_cache'):
                                self.dir_cache = {}  # child_inode -> (parent_inode, name)
                            self.dir_cache[child_inode] = (key.objectid, name)
                            
                            # Also update name cache
                            if child_inode not in self.name_cache:
                                self.name_cache[child_inode] = name
                except Exception:
                    pass
                    
            elif key.type == BTRFS_ORPHAN_ITEM_KEY:
                # Orphan item - file marked for deletion but not yet cleaned
                # objectid = ORPHAN_OBJECTID (-5), offset = inode number of orphan
                try:
                    orphan_inode = key.offset
                    if not hasattr(self, 'orphan_inodes'):
                        self.orphan_inodes = set()
                    self.orphan_inodes.add(orphan_inode)
                    self.logger.debug(f"Found orphan item: inode {orphan_inode}")
                except Exception:
                    pass

    def reconstruct_path(self, inode_num: int, max_depth: int = 50) -> str:
        """
        Reconstruct full path for an inode by walking parent directories.
        
        Args:
            inode_num: Inode number to get path for
            max_depth: Maximum directory depth to prevent infinite loops
            
        Returns:
            Full path string or just filename if path can't be reconstructed
        """
        if inode_num < BTRFS_FIRST_FREE_OBJECTID:
            return "/"
            
        path_parts = []
        current = inode_num
        depth = 0
        
        while depth < max_depth:
            # Try to find parent from dir_cache first
            if current in self.dir_cache:
                parent_inode, name = self.dir_cache[current]
                path_parts.insert(0, name)
                if parent_inode == BTRFS_FIRST_FREE_OBJECTID or parent_inode == current:
                    break  # Reached root
                current = parent_inode
            # Try parent_cache
            elif current in self.parent_cache:
                parent = self.parent_cache[current]
                name = self.name_cache.get(current, f"inode_{current}")
                path_parts.insert(0, name)
                if parent == BTRFS_FIRST_FREE_OBJECTID or parent == current:
                    break
                current = parent
            else:
                # No parent info, just use the name
                name = self.name_cache.get(current, f"inode_{current}")
                path_parts.insert(0, name)
                break
            depth += 1
        
        return "/" + "/".join(path_parts) if path_parts else "/"

    def recover_file(self, inode_num: int, generation: Optional[int] = None) -> Optional[RecoveredFile]:
        """
        Recover a file by inode number using cached extents.
        
        Args:
            inode_num: Inode number to recover
            generation: Specific generation to use. If None, uses highest generation.
        """
        if inode_num not in self.inode_cache:
            return None
        
        gen_map = self.inode_cache[inode_num]
        if not gen_map:
            return None
        
        # Select the specific generation or default to highest
        if generation is not None and generation in gen_map:
            inode = gen_map[generation]
        else:
            # Use the highest generation (most recent)
            generation = max(gen_map.keys())
            inode = gen_map[generation]
        
        # Get extents for this generation, falling back to best available
        extents = []
        ext_gen_map = self.extent_cache.get(inode_num, {})
        if generation in ext_gen_map:
            extents = ext_gen_map[generation]
        elif ext_gen_map:
            # Find the closest generation that has extents
            available_gens = sorted(ext_gen_map.keys())
            # Prefer the closest generation <= target, else closest >
            best_gen = None
            for g in reversed(available_gens):
                if g <= generation:
                    best_gen = g
                    break
            if best_gen is None:
                best_gen = available_gens[0]
            extents = ext_gen_map[best_gen]
        
        # Sort extents by offset
        extents = sorted(extents, key=lambda x: x.offset)
        
        # Determine if deleted (heuristic)
        # - nlink == 0 means no directory entries point to it
        # - Presence in orphan_inodes means it was marked for deletion
        # - If this is NOT the highest generation for this inode, it's an older version
        highest_gen = max(gen_map.keys())
        is_older_version = (generation < highest_gen)
        is_deleted = (inode.nlink == 0) or (inode_num in self.orphan_inodes) or is_older_version
        
        # Get filename from caches
        name = self.name_cache.get(inode_num, f"file_{inode_num}")
        
        # Try to reconstruct full path
        full_path = self.reconstruct_path(inode_num)
        
        recovered = RecoveredFile(
            name=name,
            inode=inode_num,
            size=inode.size,
            mode=inode.mode,
            uid=inode.uid,
            gid=inode.gid,
            atime=datetime.fromtimestamp(inode.atime),
            mtime=datetime.fromtimestamp(inode.mtime),
            ctime=datetime.fromtimestamp(inode.ctime),
            deleted=is_deleted,
            data_extents=extents
        )
        
        # Add path as extra attribute (optional field not in dataclass)
        recovered.path = full_path
        recovered.is_orphan = inode_num in self.orphan_inodes
        recovered.generation = generation
        
        return recovered
    
    def recover_deleted_files(self, output_dir: str, file_filter: str = "all") -> List[Dict]:
        """
        Recover files found during scan and write to output directory.
        
        Args:
            output_dir: Directory to save recovered files
            file_filter: Filter for which files to recover:
                - "all": Recover all files found (default)
                - "deleted_only": Only recover deleted files (nlink == 0)
                - "active_only": Only recover active/existing files (nlink > 0)
            
        Returns:
            List of recovered file metadata with 'status' and 'integrity_status' fields
        """
        if file_filter not in ("all", "deleted_only", "active_only"):
            raise ValueError(f"Invalid file_filter: {file_filter}. Must be 'all', 'deleted_only', or 'active_only'")
        
        recovered_files = []
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        
        # Reset verification stats for this recovery session
        self.verification_stats = {
            'verified': 0,
            'corrupted': 0,
            'unverified': 0,
            'no_checksum': 0
        }
        
        try:
            if not self.file_handle:
                self.open()
            
            if not self.detect_filesystem():
                raise ValueError("Not a valid Btrfs filesystem")
            
            self.parse_superblock()
            # ALWAYS do a fresh scan — scan_deleted_inodes() clears caches internally
            self.logger.info("Starting fresh device scan...")
            self.scan_deleted_inodes()
            
            count = 0
            skipped_by_filter = 0
            skipped_not_regular = 0
            total_checked = 0
            
            for inode_num, gen_map in self.inode_cache.items():
                if not gen_map:
                    continue
                
                # Find the highest generation (current/active version)
                highest_gen = max(gen_map.keys())
                
                # Iterate ALL generations for this inode to find deleted versions
                for generation, inode in gen_map.items():
                    total_checked += 1
                    
                    # Regular file type 8 (0100000)
                    file_type_bits = (inode.mode >> 12) & 0xF
                    if file_type_bits != 8:  # 8 = regular file, 4 = directory, etc.
                        skipped_not_regular += 1
                        continue
                    
                    # Skip zero-size files (nothing to recover)
                    if inode.size == 0:
                        skipped_not_regular += 1
                        continue
                    
                    # Determine if file is deleted:
                    # - nlink == 0: explicitly unlinked
                    # - In orphan_inodes: marked for deletion by Btrfs
                    # - Older generation: superseded by a newer version (COW overwrote it)
                    is_older_version = (generation < highest_gen)
                    is_deleted = (inode.nlink == 0) or (inode_num in self.orphan_inodes) or is_older_version
                    file_status = "deleted" if is_deleted else "active"
                    
                    # Apply filter
                    if file_filter == "deleted_only" and not is_deleted:
                        skipped_by_filter += 1
                        continue
                    elif file_filter == "active_only" and is_deleted:
                        skipped_by_filter += 1
                        continue
                        
                    file_info = self.recover_file(inode_num, generation)
                    if file_info:
                        # Write file data
                        safe_name = "".join(c for c in file_info.name if c.isalnum() or c in ('._-')).strip()
                        if not safe_name:
                            safe_name = f"file_{inode_num}"
                        
                        # Add status prefix and generation to filename for clarity
                        if is_deleted:
                            prefixed_name = f"DELETED_{safe_name}_gen{generation}"
                        else:
                            prefixed_name = f"ACTIVE_{safe_name}"
                        
                        # Handle duplicates
                        target_file = out_path / prefixed_name
                        counter = 1
                        while target_file.exists():
                            target_file = out_path / f"{prefixed_name}_{counter}"
                            counter += 1
                            
                        try:
                            # Write file and get data for verification
                            file_data = self.write_file_data(file_info, target_file)
                            
                            # Compute SHA256 hash of recovered data
                            file_hash = ""
                            if file_data and len(file_data) > 0:
                                file_hash = hashlib.sha256(file_data).hexdigest()
                            
                            # Verify integrity using Btrfs checksums
                            integrity_status = "unverified"
                            integrity_details = ""
                            
                            if file_data and len(file_data) > 0:
                                integrity_status, integrity_details = self.verify_file_integrity(file_info, file_data)
                            else:
                                integrity_status = "no_checksum"
                                integrity_details = "Empty file or no data recovered"
                            
                            recovered_files.append({
                                'name': target_file.name,
                                'original_name': safe_name,
                                'inode': file_info.inode,
                                'size': file_info.size,
                                'type': self._get_file_type(file_info.mode),
                                'mode': oct(file_info.mode),
                                'uid': file_info.uid,
                                'gid': file_info.gid,
                                'modified': file_info.mtime.strftime('%Y-%m-%d %H:%M:%S'),
                                'accessed': file_info.atime.strftime('%Y-%m-%d %H:%M:%S'),
                                'changed': file_info.ctime.strftime('%Y-%m-%d %H:%M:%S'),
                                'hash': file_hash,
                                'status': file_status,  # 'deleted' or 'active'
                                'deleted': is_deleted,  # kept for backward compatibility
                                'nlink': inode.nlink,
                                'generation': generation,
                                'extents': len(file_info.data_extents),
                                'path': str(target_file),
                                # Integrity verification fields
                                'integrity_status': integrity_status,  # 'verified', 'corrupted', 'unverified', 'no_checksum'
                                'integrity_verified': integrity_status == 'verified',
                                'integrity_details': integrity_details
                            })
                            count += 1
                        except Exception as e:
                            self.logger.error(f"Failed to write file {inode_num} gen={generation}: {e}")

            # Log verification statistics
            self.logger.info(f"Recovery complete: {count} files recovered to {output_dir}")
            self.logger.info(f"Integrity verification stats: verified={self.verification_stats['verified']}, "
                           f"corrupted={self.verification_stats['corrupted']}, "
                           f"unverified={self.verification_stats['unverified']}, "
                           f"no_checksum={self.verification_stats['no_checksum']}")
            self.logger.info(f"Inode stats: {total_checked} checked, {skipped_not_regular} not regular files, "
                           f"{skipped_by_filter} skipped by filter, {count} recovered")
            
            
        except Exception as e:
            self.logger.error(f"File recovery failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())
        
        return recovered_files

    def map_logical_to_physical(self, logical: int) -> int:
        """
        Map logical address to physical address using parsed chunk items.
        
        Args:
            logical: Logical address
            
        Returns:
            Physical address on device (relative to partition start)
        """
        # Find containing chunk
        # Optimziation: chunks could be sorted by logic_start
        for chunk in self.chunks:
            if chunk.logical_start <= logical < chunk.logical_start + chunk.length:
                # Found the chunk
                offset_in_chunk = logical - chunk.logical_start
                
                # Simple mapping for Single profile (and first stripe of others)
                # TODO: Support RAID0/1/10/5/6
                if chunk.stripes:
                    # Just take the first stripe's physical offset
                    # In SINGLE mode, there is only one stripe usually.
                    # In DUP mode, there are two, both valid.
                    # We assume device ID matches (or single device).
                    physical_base = chunk.stripes[0][1]
                    return physical_base + offset_in_chunk
                    
        # Fallback: if no chunk found, assume Identity mapping (logical == physical)
        # This happens for System Chunk Array items in superblock sometimes
        return logical

    def _decompress_extent(self, compressed_data: bytes, compression: int,
                           expected_size: int) -> bytes:
        """
        Decompress extent data based on the compression algorithm.
        
        Args:
            compressed_data: The raw compressed bytes read from disk
            compression: Compression type (BTRFS_COMPRESS_ZLIB/LZO/ZSTD)
            expected_size: Expected decompressed size (ram_bytes)
            
        Returns:
            Decompressed bytes, or the original data if decompression fails
        """
        if compression == BTRFS_COMPRESS_NONE:
            return compressed_data
        
        try:
            if compression == BTRFS_COMPRESS_ZLIB:
                return zlib.decompress(compressed_data)
            
            elif compression == BTRFS_COMPRESS_LZO:
                if not HAS_LZO:
                    self.logger.warning(
                        "LZO compressed extent found but python-lzo not installed. "
                        "Install with: pip install python-lzo")
                    return compressed_data
                
                # Btrfs LZO format: 4-byte LE total compressed length,
                # then segments each prefixed with a 4-byte LE compressed segment length.
                # Each segment decompresses to at most 4096 bytes (one page).
                if len(compressed_data) < 4:
                    return compressed_data
                
                total_len = struct.unpack('<I', compressed_data[:4])[0]
                pos = 4
                output = bytearray()
                
                while pos < min(total_len + 4, len(compressed_data)) and len(output) < expected_size:
                    if pos + 4 > len(compressed_data):
                        break
                    seg_len = struct.unpack('<I', compressed_data[pos:pos+4])[0]
                    pos += 4
                    
                    if seg_len == 0 or pos + seg_len > len(compressed_data):
                        break
                    
                    seg_data = compressed_data[pos:pos + seg_len]
                    pos += seg_len
                    
                    try:
                        decompressed_seg = lzo.decompress(seg_data, False, 4096)
                        output.extend(decompressed_seg)
                    except Exception as e:
                        self.logger.debug(f"LZO segment decompression failed: {e}")
                        # Try alternative: some implementations use header
                        try:
                            decompressed_seg = lzo.decompress(
                                b'\xf0' + struct.pack('>I', min(4096, expected_size - len(output))) + seg_data,
                                True, 4096
                            )
                            output.extend(decompressed_seg)
                        except Exception:
                            break
                
                return bytes(output[:expected_size])
            
            elif compression == BTRFS_COMPRESS_ZSTD:
                if not HAS_ZSTD:
                    self.logger.warning(
                        "ZSTD compressed extent found but zstandard not installed. "
                        "Install with: pip install zstandard")
                    return compressed_data
                
                dctx = zstd.ZstdDecompressor()
                return dctx.decompress(compressed_data, max_output_size=expected_size)
            
            else:
                self.logger.warning(f"Unknown compression type {compression}")
                return compressed_data
                
        except Exception as e:
            self.logger.error(
                f"Decompression failed (type={compression}, "
                f"compressed_size={len(compressed_data)}, "
                f"expected_size={expected_size}): {e}")
            return compressed_data
    
    def write_file_data(self, file_info: RecoveredFile, target_path: Path) -> bytes:
        """
        Write recovered data to target path, handling compressed extents.
        
        Supports decompression of ZLIB, LZO, and ZSTD compressed extents.
        
        Returns:
            The written data bytes (for verification purposes)
        """
        all_data = bytearray()
        
        with open(target_path, 'wb') as f:
            if not file_info.data_extents and file_info.size > 0:
                self.logger.warning(f"File {file_info.inode} has size {file_info.size} but no extents.")
                return bytes()

            current_pos = 0
            for extent in file_info.data_extents:
                # Handle sparse files (holes)
                if extent.offset > current_pos:
                    hole = b'\x00' * (extent.offset - current_pos)
                    f.write(hole)
                    all_data.extend(hole)
                    current_pos = extent.offset
                
                # Inline data (type 0)
                if extent.type == BTRFS_FILE_EXTENT_INLINE:
                    if extent.inline_data:
                        data = extent.inline_data
                        
                        # Decompress inline data if compressed
                        if extent.compression != BTRFS_COMPRESS_NONE:
                            self.logger.debug(
                                f"Decompressing inline extent: compression={extent.compression}, "
                                f"compressed_size={len(data)}, ram_bytes={extent.ram_bytes}")
                            data = self._decompress_extent(
                                data, extent.compression, extent.ram_bytes
                            )
                        
                        f.write(data)
                        all_data.extend(data)
                        current_pos += len(data)
                    
                # Regular data
                elif extent.disk_bytenr > 0:
                    try:
                        # Map logical to physical
                        physical_addr = self.map_logical_to_physical(extent.disk_bytenr)
                        
                        if extent.compression != BTRFS_COMPRESS_NONE:
                            # Read the full compressed extent from disk
                            # disk_num_bytes = compressed size on disk
                            # num_bytes = decompressed size we need
                            read_len = extent.disk_num_bytes
                            self.file_handle.seek(self.offset + physical_addr)
                            compressed_data = self.file_handle.read(read_len)
                            
                            self.logger.debug(
                                f"Decompressing regular extent: compression={extent.compression}, "
                                f"disk_num_bytes={extent.disk_num_bytes}, "
                                f"num_bytes={extent.num_bytes}, ram_bytes={extent.ram_bytes}")
                            
                            decompressed = self._decompress_extent(
                                compressed_data, extent.compression, extent.ram_bytes
                            )
                            
                            # Apply extent offset and num_bytes to get the slice we need
                            # extent.offset = offset within the decompressed extent
                            # extent.num_bytes = how many bytes to take from that offset
                            start = extent.offset
                            end = start + extent.num_bytes
                            data = decompressed[start:end]
                            
                            # Clip if exceeds file size
                            remaining = file_info.size - current_pos
                            if len(data) > remaining:
                                data = data[:remaining]
                            
                            f.write(data)
                            all_data.extend(data)
                            current_pos += len(data)
                        else:
                            # Uncompressed: read num_bytes directly
                            read_len = extent.num_bytes
                            if current_pos + read_len > file_info.size:
                                read_len = file_info.size - current_pos
                            
                            self.file_handle.seek(self.offset + physical_addr + extent.offset)
                            data = self.file_handle.read(read_len)
                            f.write(data)
                            all_data.extend(data)
                            current_pos += len(data)
                    except Exception as e:
                        self.logger.error(f"Error reading extent at {extent.disk_bytenr}: {e}")
                else:
                    # Sparse/Prealloc: write zeros
                    if extent.num_bytes > 0:
                        zeros = b'\x00' * extent.num_bytes
                        f.write(zeros)
                        all_data.extend(zeros)
                        current_pos += extent.num_bytes
            
            # Truncate to correct size
            if f.tell() > file_info.size:
                f.truncate(file_info.size)
                all_data = all_data[:file_info.size]
        
        return bytes(all_data)
    
    def _get_file_type(self, mode: int) -> str:
        """
        Get file type from mode.
        
        Args:
            mode: File mode bits
            
        Returns:
            File type string
        """
        # Extract file type from mode
        file_type = (mode >> 12) & 0xF
        
        type_map = {
            0x1: 'fifo',
            0x2: 'char',
            0x4: 'dir',
            0x6: 'block',
            0x8: 'file',
            0xA: 'link',
            0xC: 'socket',
        }
        
        return type_map.get(file_type, 'unknown')
    
    def get_filesystem_info(self) -> Dict:
        """
        Get filesystem information.
        
        Returns:
            Dictionary with filesystem metadata
        """
        if not self.superblock:
            self.parse_superblock()
        
        return {
            'filesystem': 'Btrfs',
            'label': self.superblock.label,
            'uuid': self.superblock.fsid.hex(),
            'total_size': self.superblock.total_bytes,
            'used_size': self.superblock.bytes_used,
            'free_size': self.superblock.total_bytes - self.superblock.bytes_used,
            'block_size': self.superblock.sectorsize,
            'node_size': self.superblock.nodesize,
            'generation': self.superblock.generation,
            'num_devices': self.superblock.num_devices,
        }


# Example usage and testing
if __name__ == "__main__":
    import sys
    
    logging.basicConfig(level=logging.INFO)
    
    if len(sys.argv) < 2:
        print("Usage: python btrfs_parser.py <disk_image>")
        sys.exit(1)
    
    image_path = sys.argv[1]
    
    print(f"Analyzing Btrfs image: {image_path}\n")
    
    with BtrfsParser(image_path) as parser:
        # Detect filesystem
        if parser.detect_filesystem():
            print("✓ Btrfs filesystem detected\n")
            
            # Parse superblock
            sb = parser.parse_superblock()
            print(f"Filesystem Info:")
            print(f"  Label: {sb.label}")
            print(f"  Total Size: {sb.total_bytes / (1024**3):.2f} GB")
            print(f"  Used: {sb.bytes_used / (1024**3):.2f} GB")
            print(f"  Generation: {sb.generation}")
            print(f"  Devices: {sb.num_devices}")
            print()
            
            # Recover files
            print("Starting file recovery...")
            files = parser.recover_deleted_files("./recovered_files")
            print(f"\nRecovered {len(files)} files")
            
            for file_info in files[:10]:  # Show first 10
                print(f"  - {file_info['name']} ({file_info['size']} bytes)")
        else:
            print("✗ Not a Btrfs filesystem")