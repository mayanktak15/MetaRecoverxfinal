"""
Unearth Forensic Recovery Tool - XFS Filesystem Parser
Handles XFS-specific structures and recovery operations

XFS Features Supported:
- Superblock parsing
- Allocation Group (AG) analysis
- Inode scanning and recovery
- Extent-based file data recovery
- Deleted file detection (zeroed di_mode with preserved extents)
- SHA256 hash verification

Author: Unearth Development Team
Version: 1.0.0
"""

import struct
import logging
import hashlib
import os
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set
from datetime import datetime
from dataclasses import dataclass, field


# ============================================================
# XFS Constants
# ============================================================

XFS_MAGIC = 0x58465342  # 'XFSB'
XFS_MAGIC_BYTES = b'XFSB'
XFS_AGF_MAGIC = 0x58414746  # 'XAGF'
XFS_AGI_MAGIC = 0x58414749  # 'XAGI'
XFS_DINODE_MAGIC = 0x494E  # 'IN'

# Inode format types (di_format)
XFS_DINODE_FMT_DEV = 0       # Device
XFS_DINODE_FMT_LOCAL = 1     # Inline data
XFS_DINODE_FMT_EXTENTS = 2   # Extent list
XFS_DINODE_FMT_BTREE = 3     # B+tree
XFS_DINODE_FMT_UUID = 4      # UUID (not used for files)

# File type constants from di_mode (S_IFMT mask = 0xF000)
S_IFMT = 0o170000
S_IFREG = 0o100000   # Regular file
S_IFDIR = 0o040000   # Directory
S_IFLNK = 0o120000   # Symbolic link
S_IFBLK = 0o060000   # Block device
S_IFCHR = 0o020000   # Character device
S_IFIFO = 0o010000   # FIFO
S_IFSOCK = 0o140000  # Socket

# Superblock feature flags
XFS_SB_VERSION_NLINKBIT = 0x1000
XFS_SB_VERSION2_FTYPE = 0x0200

# Inode core size (v2 = 100 bytes, v3 = 176 bytes)
XFS_DINODE_CORE_V2_SIZE = 96
XFS_DINODE_CORE_V3_SIZE = 176

# B+tree magic numbers
XFS_BMAP_MAGIC = 0x424D4150       # 'BMAP' short format
XFS_BMAP_CRC_MAGIC = 0x424D4133   # 'BMA3' long format (v5)

# AGF free-space B+tree magic numbers
XFS_ABTB_MAGIC = 0x41425442       # 'ABTB' — bnobt v4
XFS_ABTB_CRC_MAGIC = 0x41423342   # 'AB3B' — bnobt v5

# AGI unlinked buckets
XFS_AGI_UNLINKED_BUCKETS = 64
XFS_AGI_UNLINKED_OFFSET = 72      # Byte offset in AGI header where buckets start
NULLAGINO = 0xFFFFFFFF            # Sentinel for empty unlinked bucket

# AG header sizes
XFS_AGF_SIZE = 224
XFS_AGI_SIZE = 336

# Inode chunk size
XFS_INODES_PER_CHUNK = 64


# ============================================================
# Data Structures
# ============================================================

@dataclass
class XfsSuperblock:
    """XFS Primary Superblock structure"""
    magicnum: int
    blocksize: int
    dblocks: int          # Total data blocks
    rblocks: int          # Realtime blocks
    rextents: int         # Realtime extents
    uuid: bytes
    logstart: int         # Log start block
    rootino: int          # Root inode number
    agcount: int          # Number of allocation groups
    agblocks: int         # Blocks per AG
    sectsize: int         # Sector size (bytes)
    inodesize: int        # Inode size (bytes)
    inopblock: int        # Inodes per block
    fname: str            # Filesystem name
    blocklog: int         # log2(blocksize)
    sectlog: int          # log2(sectsize)
    inodelog: int         # log2(inodesize)
    inopblog: int         # log2(inopblock)
    agblklog: int         # log2(agblocks)
    sb_versionnum: int    # Version/feature flags
    sb_features2: int     # Additional features
    sb_icount: int        # Allocated inodes
    sb_ifree: int         # Free inodes
    sb_fdblocks: int      # Free data blocks


@dataclass
class XfsAgfHeader:
    """XFS Allocation Group Free-space header"""
    magicnum: int
    versionnum: int
    seqno: int            # AG number
    length: int           # AG length in blocks
    freeblks: int         # Free blocks in AG
    longest: int          # Longest free extent
    bno_root: int = 0     # Block-number-ordered free-space B+tree root
    bno_level: int = 0    # bnobt tree levels


@dataclass
class XfsAgiHeader:
    """XFS Allocation Group Inode header"""
    magicnum: int
    versionnum: int
    seqno: int            # AG number
    count: int            # Allocated inodes
    root: int             # Inode B+tree root block
    level: int            # B+tree levels
    freecount: int        # Free inodes
    newino: int           # Last allocated inode
    length: int           # AG length in blocks


@dataclass
class XfsInodeCore:
    """XFS on-disk inode core structure"""
    di_magic: int         # 'IN' (0x494E)
    di_mode: int          # File type and permissions
    di_version: int       # Inode version (2 or 3)
    di_format: int        # Data fork format
    di_uid: int           # Owner UID
    di_gid: int           # Owner GID
    di_nlink: int         # Number of hard links
    di_projid: int        # Project ID
    di_atime: int         # Access time (epoch)
    di_mtime: int         # Modification time (epoch)
    di_ctime: int         # Change time (epoch)
    di_size: int          # File size in bytes
    di_nblocks: int       # Number of blocks used
    di_extsize: int       # Extent size hint
    di_nextents: int      # Number of data extents
    di_anextents: int     # Number of attr extents
    di_forkoff: int       # Attr fork offset (8-byte units)
    di_aformat: int       # Attr fork format
    di_gen: int           # Generation number
    # v3 fields
    di_crtime: int = 0    # Creation time (v3 only)
    di_ino: int = 0       # Inode number (v3 only)


@dataclass
class XfsExtent:
    """XFS extent record (decoded from 128-bit packed format)"""
    startoff: int         # Logical file offset (in blocks)
    startblock: int       # Absolute disk block number
    blockcount: int       # Number of blocks
    flag: int             # 0=normal, 1=unwritten/preallocated


@dataclass
class XfsRecoveredFile:
    """Recovered file information"""
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
    extents: List[XfsExtent]
    checksum: Optional[str] = None
    integrity_status: str = "unverified"
    integrity_verified: bool = False
    integrity_details: str = ""


# ============================================================
# XFS Parser
# ============================================================

class XfsParser:
    """
    XFS Filesystem Parser

    Parses XFS filesystem structures and recovers deleted files.
    Exploits the fact that XFS zeroes di_mode and di_size on deletion
    but preserves extent lists, allowing data reconstruction.
    """

    def __init__(self, image_path: str, offset: int = 0, progress_callback=None):
        """
        Initialize XFS parser.

        Args:
            image_path: Path to disk image or device
            offset: Byte offset where filesystem starts (for partitioned images)
            progress_callback: Optional callback(current, total, message)
        """
        self.image_path = Path(image_path)
        self.offset = offset
        self.progress_callback = progress_callback
        self.logger = logging.getLogger(__name__)
        self.superblock: Optional[XfsSuperblock] = None
        self.file_handle = None

        # AG metadata caches
        self.ag_headers: List[Tuple[XfsAgfHeader, XfsAgiHeader]] = []

        # Inode caches
        self.inode_cache: Dict[int, XfsInodeCore] = {}
        self.extent_cache: Dict[int, List[XfsExtent]] = {}
        self.name_cache: Dict[int, str] = {}
        self.dir_entries: Dict[int, List[Tuple[int, str]]] = {}  # parent_ino -> [(child_ino, name)]

        # Free-space block ranges for overlap/reallocation detection
        # Each entry is (abs_start_block, block_count)
        self.free_block_ranges: List[Tuple[int, int]] = []
        self._free_block_set: Optional[set] = None  # Lazily built set of free block numbers

        # Fragmented recovery statistics
        self.fragmented_recovery_stats = {
            'unlinked_inodes_found': 0,
            'salvaged_extent_inodes': 0,
            'extents_in_free_space': 0,
            'extents_possibly_overwritten': 0,
        }

        # Verification statistics
        self.verification_stats = {
            'verified': 0,
            'corrupted': 0,
            'unverified': 0,
            'no_checksum': 0
        }

        self.logger.info(f"Initialized XFS parser for {image_path}")

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
            self.file_handle = None
            self.logger.info("Image file closed")

    def __enter__(self):
        """Context manager entry"""
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

    # --------------------------------------------------------
    # Filesystem Detection
    # --------------------------------------------------------

    def detect_filesystem(self) -> bool:
        """
        Detect if the image contains an XFS filesystem.

        Returns:
            True if XFS detected, False otherwise
        """
        try:
            if not self.file_handle:
                self.open()

            self.file_handle.seek(self.offset)
            magic = self.file_handle.read(4)

            is_xfs = magic == XFS_MAGIC_BYTES

            if is_xfs:
                self.logger.info("XFS filesystem detected")
            else:
                self.logger.warning(f"Not an XFS filesystem (magic: {magic!r})")

            return is_xfs

        except Exception as e:
            self.logger.error(f"Filesystem detection failed: {e}")
            return False

    # --------------------------------------------------------
    # Superblock Parsing
    # --------------------------------------------------------

    def parse_superblock(self) -> XfsSuperblock:
        """
        Parse the XFS primary superblock (at offset 0 of the filesystem).

        Returns:
            Parsed superblock structure
        """
        try:
            self.file_handle.seek(self.offset)
            data = self.file_handle.read(512)

            if len(data) < 264:
                raise ValueError("Superblock data too short")

            magicnum = struct.unpack('>I', data[0:4])[0]
            if magicnum != XFS_MAGIC:
                raise ValueError(f"Invalid XFS magic: 0x{magicnum:08X}")

            blocksize = struct.unpack('>I', data[4:8])[0]
            dblocks = struct.unpack('>Q', data[8:16])[0]
            rblocks = struct.unpack('>Q', data[16:24])[0]
            rextents = struct.unpack('>Q', data[24:32])[0]
            uuid = data[32:48]
            logstart = struct.unpack('>Q', data[48:56])[0]
            rootino = struct.unpack('>Q', data[56:64])[0]

            # Skip rbmino(8), rsumino(8), rextsize(4)
            # Per XFS spec: offset 84 = sb_agblocks, offset 88 = sb_agcount
            val_84 = struct.unpack('>I', data[84:88])[0]
            val_88 = struct.unpack('>I', data[88:92])[0]

            sectsize = struct.unpack('>H', data[102:104])[0]
            inodesize = struct.unpack('>H', data[104:106])[0]
            inopblock = struct.unpack('>H', data[106:108])[0]

            fname_raw = data[108:120]
            fname = fname_raw.split(b'\x00')[0].decode('utf-8', errors='ignore')

            blocklog = data[120]
            sectlog = data[121]
            inodelog = data[122]
            inopblog = data[123]
            agblklog = data[124]

            # Auto-detect agblocks vs agcount using agblklog as ground truth.
            # agblklog = log2(agblocks), so agblocks should be close to 2^agblklog.
            # Also: agblocks * agcount should approximately equal dblocks.
            expected_agblocks = 1 << agblklog if agblklog > 0 else 0

            # Check which assignment makes sense
            if expected_agblocks > 0 and val_84 == expected_agblocks:
                # Standard layout: off84=agblocks, off88=agcount
                agblocks = val_84
                agcount = val_88
            elif expected_agblocks > 0 and val_88 == expected_agblocks:
                # Swapped: off84=agcount, off88=agblocks
                agblocks = val_88
                agcount = val_84
                self.logger.debug("Auto-detected swapped agcount/agblocks layout")
            else:
                # Fallback: check which ordering gives agblocks*agcount ≈ dblocks
                product_a = val_84 * val_88  # both orderings give same product
                # Use agblklog to determine which is agblocks
                # The value closer to 2^agblklog is agblocks
                diff_84 = abs(val_84 - expected_agblocks) if expected_agblocks > 0 else val_84
                diff_88 = abs(val_88 - expected_agblocks) if expected_agblocks > 0 else val_88
                if diff_84 <= diff_88:
                    agblocks = val_84
                    agcount = val_88
                else:
                    agblocks = val_88
                    agcount = val_84
                self.logger.debug(
                    f"agblklog={agblklog}, expected_agblocks={expected_agblocks}, "
                    f"val_84={val_84}, val_88={val_88} → agblocks={agblocks}, agcount={agcount}"
                )

            # rextslog(1), inprogress(1), imax_pct(1)
            sb_icount = struct.unpack('>Q', data[128:136])[0]
            sb_ifree = struct.unpack('>Q', data[136:144])[0]
            sb_fdblocks = struct.unpack('>Q', data[144:152])[0]

            # sb_frextents(8)
            # sb_uquotino(8), sb_gquotino(8), sb_qflags(2), sb_flags(1), sb_shared_vn(1)
            # ...much more, but we have the critical fields

            sb_versionnum = struct.unpack('>H', data[100:102])[0]

            # sb_features2 at offset 204
            sb_features2 = 0
            if len(data) >= 208:
                sb_features2 = struct.unpack('>I', data[204:208])[0]

            superblock = XfsSuperblock(
                magicnum=magicnum,
                blocksize=blocksize,
                dblocks=dblocks,
                rblocks=rblocks,
                rextents=rextents,
                uuid=uuid,
                logstart=logstart,
                rootino=rootino,
                agcount=agcount,
                agblocks=agblocks,
                sectsize=sectsize,
                inodesize=inodesize,
                inopblock=inopblock,
                fname=fname,
                blocklog=blocklog,
                sectlog=sectlog,
                inodelog=inodelog,
                inopblog=inopblog,
                agblklog=agblklog,
                sb_versionnum=sb_versionnum,
                sb_features2=sb_features2,
                sb_icount=sb_icount,
                sb_ifree=sb_ifree,
                sb_fdblocks=sb_fdblocks,
            )

            self.superblock = superblock
            self.logger.info(
                f"Superblock parsed: {blocksize}B blocks, "
                f"{agcount} AGs × {agblocks} blocks/AG, {inodesize}B inodes, "
                f"{dblocks * blocksize / (1024**3):.2f} GB total, "
                f"label: '{fname}'"
            )

            return superblock

        except Exception as e:
            self.logger.error(f"Failed to parse superblock: {e}")
            raise

    # --------------------------------------------------------
    # AG Header Parsing
    # --------------------------------------------------------

    def parse_ag_headers(self):
        """Parse AGF and AGI headers for all Allocation Groups."""
        if not self.superblock:
            self.parse_superblock()

        sb = self.superblock
        self.ag_headers = []

        for ag_num in range(sb.agcount):
            ag_offset = self.offset + ag_num * sb.agblocks * sb.blocksize

            # Parse AGF (sector 1 of AG)
            agf = self._parse_agf(ag_offset + sb.sectsize)

            # Parse AGI (sector 2 of AG)
            agi = self._parse_agi(ag_offset + 2 * sb.sectsize)

            self.ag_headers.append((agf, agi))
            self.logger.debug(
                f"AG {ag_num}: {agi.count} inodes allocated, "
                f"{agi.freecount} free, B+tree root block {agi.root}"
            )

    def _parse_agf(self, abs_offset: int) -> XfsAgfHeader:
        """Parse an AGF header at the given absolute offset."""
        self.file_handle.seek(abs_offset)
        data = self.file_handle.read(XFS_AGF_SIZE)

        magicnum = struct.unpack('>I', data[0:4])[0]
        versionnum = struct.unpack('>I', data[4:8])[0]
        seqno = struct.unpack('>I', data[8:12])[0]
        length = struct.unpack('>I', data[12:16])[0]
        bno_root = struct.unpack('>I', data[16:20])[0]
        # cnt_root at 20, spare at 24
        bno_level = struct.unpack('>I', data[28:32])[0]
        # cnt_level at 32
        freeblks = struct.unpack('>I', data[36:40])[0]
        longest = struct.unpack('>I', data[40:44])[0]

        return XfsAgfHeader(
            magicnum=magicnum,
            versionnum=versionnum,
            seqno=seqno,
            length=length,
            freeblks=freeblks,
            longest=longest,
            bno_root=bno_root,
            bno_level=bno_level,
        )

    def _parse_agi(self, abs_offset: int) -> XfsAgiHeader:
        """Parse an AGI header at the given absolute offset."""
        self.file_handle.seek(abs_offset)
        data = self.file_handle.read(XFS_AGI_SIZE)

        magicnum = struct.unpack('>I', data[0:4])[0]
        versionnum = struct.unpack('>I', data[4:8])[0]
        seqno = struct.unpack('>I', data[8:12])[0]
        length = struct.unpack('>I', data[12:16])[0]
        count = struct.unpack('>I', data[16:20])[0]
        root = struct.unpack('>I', data[20:24])[0]
        level = struct.unpack('>I', data[24:28])[0]
        freecount = struct.unpack('>I', data[28:32])[0]
        newino = struct.unpack('>I', data[32:36])[0]

        return XfsAgiHeader(
            magicnum=magicnum,
            versionnum=versionnum,
            seqno=seqno,
            count=count,
            root=root,
            level=level,
            freecount=freecount,
            newino=newino,
            length=length,
        )

    # --------------------------------------------------------
    # Inode Number / Block Address Translation
    # --------------------------------------------------------

    def _inode_to_location(self, inode_num: int) -> Tuple[int, int, int]:
        """
        Convert absolute inode number to AG number and byte offset.

        Returns:
            (ag_number, ag_relative_block, offset_within_block)
        """
        sb = self.superblock
        inodes_per_ag = sb.agblocks * sb.inopblock
        ag_num = inode_num // inodes_per_ag
        ag_relative_ino = inode_num % inodes_per_ag
        ag_block = ag_relative_ino // sb.inopblock
        offset_in_block = (ag_relative_ino % sb.inopblock) * sb.inodesize
        return ag_num, ag_block, offset_in_block

    def _inode_abs_offset(self, inode_num: int) -> int:
        """Get absolute byte offset of an inode on disk."""
        ag_num, ag_block, offset_in_block = self._inode_to_location(inode_num)
        sb = self.superblock
        ag_start = self.offset + ag_num * sb.agblocks * sb.blocksize
        return ag_start + ag_block * sb.blocksize + offset_in_block

    def _ag_block_to_abs(self, ag_num: int, ag_block: int) -> int:
        """Convert AG-relative block number to absolute byte offset."""
        sb = self.superblock
        return self.offset + (ag_num * sb.agblocks + ag_block) * sb.blocksize

    def _abs_block_to_bytes(self, abs_block: int) -> int:
        """Convert absolute filesystem block number to byte offset."""
        sb = self.superblock
        return self.offset + abs_block * sb.blocksize

    # --------------------------------------------------------
    # Inode Core Parsing
    # --------------------------------------------------------

    def _parse_inode_core(self, data: bytes, offset: int = 0) -> Optional[XfsInodeCore]:
        """
        Parse XFS inode core from raw data.

        Args:
            data: Raw inode data
            offset: Offset within data to start parsing

        Returns:
            Parsed inode core, or None if magic doesn't match
        """
        if len(data) < offset + XFS_DINODE_CORE_V2_SIZE:
            return None

        di_magic = struct.unpack('>H', data[offset:offset+2])[0]

        # Allow both valid magic and zeroed magic (deleted inodes)
        if di_magic != XFS_DINODE_MAGIC and di_magic != 0:
            return None

        di_mode = struct.unpack('>H', data[offset+2:offset+4])[0]
        di_version = data[offset + 4]
        di_format = data[offset + 5]
        di_uid = struct.unpack('>I', data[offset+8:offset+12])[0]
        di_gid = struct.unpack('>I', data[offset+12:offset+16])[0]
        di_nlink = struct.unpack('>I', data[offset+16:offset+20])[0]
        di_projid = struct.unpack('>H', data[offset+20:offset+22])[0]

        # Timestamps (seconds since epoch, big-endian 32-bit)
        di_atime = struct.unpack('>I', data[offset+32:offset+36])[0]
        di_mtime = struct.unpack('>I', data[offset+40:offset+44])[0]
        di_ctime = struct.unpack('>I', data[offset+48:offset+52])[0]

        di_size = struct.unpack('>Q', data[offset+56:offset+64])[0]
        di_nblocks = struct.unpack('>Q', data[offset+64:offset+72])[0]
        di_extsize = struct.unpack('>I', data[offset+72:offset+76])[0]
        di_nextents = struct.unpack('>I', data[offset+76:offset+80])[0]
        di_anextents = struct.unpack('>H', data[offset+80:offset+82])[0]
        di_forkoff = data[offset + 82]
        di_aformat = data[offset + 83]
        di_gen = struct.unpack('>I', data[offset+84:offset+88])[0]

        di_crtime = 0
        di_ino = 0
        if di_version == 3 and len(data) >= offset + XFS_DINODE_CORE_V3_SIZE:
            # v3 has additional CRC, change count, lsn, flags, etc.
            # crtime at offset 104..111 (sec + nsec)
            if len(data) >= offset + 112:
                di_crtime = struct.unpack('>I', data[offset+104:offset+108])[0]
            # ino at offset 152
            if len(data) >= offset + 160:
                di_ino = struct.unpack('>Q', data[offset+152:offset+160])[0]

        return XfsInodeCore(
            di_magic=di_magic,
            di_mode=di_mode,
            di_version=di_version,
            di_format=di_format,
            di_uid=di_uid,
            di_gid=di_gid,
            di_nlink=di_nlink,
            di_projid=di_projid,
            di_atime=di_atime,
            di_mtime=di_mtime,
            di_ctime=di_ctime,
            di_size=di_size,
            di_nblocks=di_nblocks,
            di_extsize=di_extsize,
            di_nextents=di_nextents,
            di_anextents=di_anextents,
            di_forkoff=di_forkoff,
            di_aformat=di_aformat,
            di_gen=di_gen,
            di_crtime=di_crtime,
            di_ino=di_ino,
        )

    # --------------------------------------------------------
    # Extent Decoding
    # --------------------------------------------------------

    def _decode_extent(self, data: bytes, offset: int = 0) -> XfsExtent:
        """
        Decode a 128-bit (16-byte) XFS extent record.

        XFS extent format (big-endian, 128 bits total):
            Bit 127      : flag (1 bit) — 0=normal, 1=unwritten
            Bits 126-73  : startoff (54 bits) — logical file offset in blocks
            Bits 72-21   : startblock (52 bits) — absolute block number
            Bits 20-0    : blockcount (21 bits) — number of blocks
        """
        # Read as two 64-bit big-endian integers
        hi = struct.unpack('>Q', data[offset:offset+8])[0]
        lo = struct.unpack('>Q', data[offset+8:offset+16])[0]

        # Combine into 128-bit value
        val = (hi << 64) | lo

        flag = (val >> 127) & 0x1
        startoff = (val >> 73) & ((1 << 54) - 1)
        startblock = (val >> 21) & ((1 << 52) - 1)
        blockcount = val & ((1 << 21) - 1)

        return XfsExtent(
            startoff=startoff,
            startblock=startblock,
            blockcount=blockcount,
            flag=flag,
        )

    def _read_extents_from_inode(self, inode_data: bytes, inode_core: XfsInodeCore) -> List[XfsExtent]:
        """
        Read extent list from the inode data fork.

        For XFS_DINODE_FMT_EXTENTS: extents are stored inline after the inode core.
        For XFS_DINODE_FMT_BTREE: root of B+tree is inline, need to traverse.

        Args:
            inode_data: Complete raw inode data (inodesize bytes)
            inode_core: Parsed inode core

        Returns:
            List of decoded extents
        """
        extents = []

        # Determine data fork offset (after inode core)
        if inode_core.di_version == 3:
            data_fork_offset = XFS_DINODE_CORE_V3_SIZE
        else:
            data_fork_offset = XFS_DINODE_CORE_V2_SIZE

        # Determine data fork size
        if inode_core.di_forkoff > 0:
            data_fork_size = inode_core.di_forkoff * 8
        else:
            data_fork_size = len(inode_data) - data_fork_offset

        if inode_core.di_format == XFS_DINODE_FMT_EXTENTS:
            # Direct extent list — each extent is 16 bytes
            num_extents = inode_core.di_nextents
            if num_extents == 0:
                return extents

            # Sanity check
            max_extents = data_fork_size // 16
            num_extents = min(num_extents, max_extents)

            for i in range(num_extents):
                ext_offset = data_fork_offset + i * 16
                if ext_offset + 16 > len(inode_data):
                    break
                ext = self._decode_extent(inode_data, ext_offset)
                if ext.blockcount > 0 and ext.startblock > 0:
                    extents.append(ext)

        elif inode_core.di_format == XFS_DINODE_FMT_BTREE:
            # B+tree root is stored in data fork
            extents = self._walk_bmbt_tree(inode_data, data_fork_offset, data_fork_size)

        return extents

    def _walk_bmbt_tree(self, inode_data: bytes, fork_offset: int, fork_size: int) -> List[XfsExtent]:
        """
        Walk a B+tree extent map (BMBT) from the root stored in the inode.

        The root node is stored inline in the data fork:
            - bb_level (2 bytes): tree level (0 = leaf)
            - bb_numrecs (2 bytes): number of records/keys
            - Then either keys+pointers (internal) or extent records (leaf)
        """
        extents = []

        if fork_size < 4:
            return extents

        bb_level = struct.unpack('>H', inode_data[fork_offset:fork_offset+2])[0]
        bb_numrecs = struct.unpack('>H', inode_data[fork_offset+2:fork_offset+4])[0]

        if bb_level == 0:
            # Leaf node — records are directly here
            rec_offset = fork_offset + 4
            for i in range(bb_numrecs):
                off = rec_offset + i * 16
                if off + 16 > len(inode_data):
                    break
                ext = self._decode_extent(inode_data, off)
                if ext.blockcount > 0 and ext.startblock > 0:
                    extents.append(ext)
        else:
            # Internal node — keys followed by block pointers
            keys_offset = fork_offset + 4
            # Keys are 16 bytes each (startoff + startblock), pointers are 8 bytes (block number)
            ptrs_offset = keys_offset + bb_numrecs * 16

            for i in range(bb_numrecs):
                ptr_off = ptrs_offset + i * 8
                if ptr_off + 8 > len(inode_data):
                    break
                child_block = struct.unpack('>Q', inode_data[ptr_off:ptr_off+8])[0]
                child_extents = self._read_bmbt_block(child_block, bb_level - 1)
                extents.extend(child_extents)

        return extents

    def _read_bmbt_block(self, abs_block: int, level: int) -> List[XfsExtent]:
        """Read a BMBT block from disk and extract extents."""
        extents = []
        sb = self.superblock

        byte_offset = self._abs_block_to_bytes(abs_block)
        self.file_handle.seek(byte_offset)
        block_data = self.file_handle.read(sb.blocksize)

        if len(block_data) < sb.blocksize:
            return extents

        # Determine header size based on magic
        magic = struct.unpack('>I', block_data[0:4])[0]
        if magic == XFS_BMAP_CRC_MAGIC:
            # v5 long format header: magic(4) + level(2) + numrecs(2) + leftsib(8) + rightsib(8) + ...
            header_size = 72
        elif magic == XFS_BMAP_MAGIC:
            # Short format header: magic(4) + level(2) + numrecs(2) + leftsib(4) + rightsib(4)
            header_size = 16
        else:
            # Try assuming short header
            header_size = 16

        bb_level = struct.unpack('>H', block_data[4:6])[0]
        bb_numrecs = struct.unpack('>H', block_data[6:8])[0]

        if bb_level == 0:
            # Leaf: extent records after header
            for i in range(bb_numrecs):
                off = header_size + i * 16
                if off + 16 > len(block_data):
                    break
                ext = self._decode_extent(block_data, off)
                if ext.blockcount > 0 and ext.startblock > 0:
                    extents.append(ext)
        else:
            # Internal: keys + pointers
            keys_start = header_size
            ptrs_start = keys_start + bb_numrecs * 16

            for i in range(bb_numrecs):
                ptr_off = ptrs_start + i * 8
                if ptr_off + 8 > len(block_data):
                    break
                child_block = struct.unpack('>Q', block_data[ptr_off:ptr_off+8])[0]
                child_extents = self._read_bmbt_block(child_block, level - 1)
                extents.extend(child_extents)

        return extents

    # --------------------------------------------------------
    # Directory Parsing (for filename recovery)
    # --------------------------------------------------------

    def _parse_shortform_dir(self, inode_data: bytes, core: XfsInodeCore) -> List[Tuple[int, str]]:
        """Parse a short-form (inline) directory to get (inode_num, name) entries."""
        entries = []
        if core.di_version == 3:
            fork_offset = XFS_DINODE_CORE_V3_SIZE
        else:
            fork_offset = XFS_DINODE_CORE_V2_SIZE

        if fork_offset + 6 > len(inode_data):
            return entries

        # Short-form directory header
        sf_count = inode_data[fork_offset]
        # sf_i8count = inode_data[fork_offset + 1]
        parent_ino = struct.unpack('>I', inode_data[fork_offset+2:fork_offset+6])[0]

        pos = fork_offset + 6
        has_ftype = bool(self.superblock.sb_features2 & XFS_SB_VERSION2_FTYPE)

        for _ in range(sf_count):
            if pos + 3 > len(inode_data):
                break

            namelen = inode_data[pos]
            pos += 1
            # offset (2 bytes) — not needed for our purposes
            pos += 2

            if pos + namelen > len(inode_data):
                break
            name = inode_data[pos:pos+namelen].decode('utf-8', errors='replace')
            pos += namelen

            if has_ftype:
                pos += 1  # skip ftype byte

            # Inode number (4 bytes for i8count=0)
            if pos + 4 > len(inode_data):
                break
            child_ino = struct.unpack('>I', inode_data[pos:pos+4])[0]
            pos += 4

            if name not in ('.', '..') and child_ino > 0:
                entries.append((child_ino, name))

        return entries

    def _parse_block_dir(self, extents: List[XfsExtent]) -> List[Tuple[int, str]]:
        """Parse block/leaf/node directory format from extent data."""
        entries = []
        sb = self.superblock

        for ext in extents:
            # Only read the first data extent for directory entries
            if ext.startoff > 0:
                continue  # Skip leaf/free blocks (high logical offsets)

            byte_offset = self._abs_block_to_bytes(ext.startblock)
            read_size = ext.blockcount * sb.blocksize
            if read_size > 1024 * 1024:  # Cap at 1MB for safety
                read_size = 1024 * 1024

            self.file_handle.seek(byte_offset)
            data = self.file_handle.read(read_size)

            # Walk variable-length directory entries
            # XFS block dir header: magic(4) + ...
            # Data entries start after the header (depends on version)
            pos = 16  # Skip basic header
            has_ftype = bool(sb.sb_features2 & XFS_SB_VERSION2_FTYPE)

            while pos + 12 < len(data):
                # Each entry: inumber(8) + namelen(1) + name(namelen) + [ftype(1)] + tag(2)
                inumber = struct.unpack('>Q', data[pos:pos+8])[0]
                if inumber == 0:
                    # Free entry or end — skip 8 bytes
                    pos += 8
                    continue

                namelen = data[pos + 8]
                if namelen == 0 or pos + 9 + namelen > len(data):
                    break

                name = data[pos+9:pos+9+namelen].decode('utf-8', errors='replace')

                # Calculate entry size (8-byte aligned)
                entry_size = 9 + namelen
                if has_ftype:
                    entry_size += 1
                entry_size += 2  # tag
                entry_size = (entry_size + 7) & ~7  # Round up to 8-byte boundary

                if name not in ('.', '..') and inumber > 0:
                    entries.append((inumber, name))

                pos += entry_size

        return entries

    # --------------------------------------------------------
    # Inode Scanning
    # --------------------------------------------------------

    def scan_all_inodes(self):
        """
        Scan all Allocation Groups for inodes.

        Walks the inode B+tree in each AG and reads all allocated
        inode chunks (64 inodes per chunk). Populates inode_cache,
        extent_cache, and attempts filename recovery from directories.
        """
        if not self.superblock:
            self.parse_superblock()
        if not self.ag_headers:
            self.parse_ag_headers()

        sb = self.superblock
        total_ags = sb.agcount
        total_inodes_scanned = 0

        self.logger.info(f"Scanning {total_ags} allocation groups for inodes...")

        for ag_num in range(total_ags):
            if self.progress_callback:
                self.progress_callback(ag_num, total_ags, f"Scanning AG {ag_num}/{total_ags}")

            agf, agi = self.ag_headers[ag_num]
            inodes_per_ag = sb.agblocks * sb.inopblock

            # Walk the inode B+tree to find allocated inode chunks
            inode_chunks = self._walk_agi_btree(ag_num, agi.root, agi.level)

            for chunk_start_ino in inode_chunks:
                # Each chunk is 64 inodes
                for i in range(XFS_INODES_PER_CHUNK):
                    abs_ino = ag_num * inodes_per_ag + chunk_start_ino + i

                    try:
                        abs_offset = self._inode_abs_offset(abs_ino)
                        
                        # Bounds check: ensure offset is within the image
                        if abs_offset < 0:
                            continue
                        
                        self.file_handle.seek(abs_offset)
                        raw_inode = self.file_handle.read(sb.inodesize)

                        if len(raw_inode) < sb.inodesize:
                            continue

                        core = self._parse_inode_core(raw_inode, 0)
                        if core is None:
                            continue

                        # Skip completely free/unallocated inodes (no magic, no data)
                        if core.di_magic == 0 and core.di_nblocks == 0 and core.di_nextents == 0:
                            continue

                        self.inode_cache[abs_ino] = core

                        # Diagnostic: log details of first few meaningful inodes
                        if total_inodes_scanned < 10:
                            mode_type = (core.di_mode & S_IFMT) >> 12 if core.di_mode else 0
                            self.logger.info(
                                f"  Inode {abs_ino}: magic=0x{core.di_magic:04X} "
                                f"mode=0o{core.di_mode:06o}(type={mode_type}) "
                                f"ver={core.di_version} fmt={core.di_format} "
                                f"size={core.di_size} nblocks={core.di_nblocks} "
                                f"nextents={core.di_nextents} nlink={core.di_nlink} "
                                f"forkoff={core.di_forkoff}"
                            )

                        # Read extents for files with extent data
                        if core.di_nextents > 0 or core.di_format in (
                            XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE
                        ):
                            exts = self._read_extents_from_inode(raw_inode, core)
                            if exts:
                                self.extent_cache[abs_ino] = exts

                        # Speculative extent salvage for deleted inodes
                        # whose extent count was zeroed but data fork
                        # may still contain valid extent records
                        if abs_ino not in self.extent_cache:
                            salvaged = self._try_salvage_extents_for_inode(
                                raw_inode, core
                            )
                            if salvaged:
                                self.extent_cache[abs_ino] = salvaged

                        # Parse directories for filename recovery
                        if (core.di_mode & S_IFMT) == S_IFDIR and core.di_size > 0:
                            if core.di_format == XFS_DINODE_FMT_LOCAL:
                                dir_entries = self._parse_shortform_dir(raw_inode, core)
                            elif core.di_format in (XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE):
                                dir_extents = self.extent_cache.get(abs_ino, [])
                                dir_entries = self._parse_block_dir(dir_extents)
                            else:
                                dir_entries = []

                            self.dir_entries[abs_ino] = dir_entries
                            for child_ino, child_name in dir_entries:
                                self.name_cache[child_ino] = child_name

                        total_inodes_scanned += 1

                    except Exception as e:
                        self.logger.debug(f"Error reading inode {abs_ino}: {e}")
                        continue

        self.logger.info(
            f"Inode scan complete: {total_inodes_scanned} inodes scanned, "
            f"{len(self.inode_cache)} cached, "
            f"{len(self.extent_cache)} with extents, "
            f"{len(self.name_cache)} names recovered"
        )

    def _walk_agi_btree(self, ag_num: int, root_block: int, level: int, depth: int = 0) -> List[int]:
        """
        Walk the inode B+tree (inobt) to find allocated inode chunk offsets.

        Returns:
            List of AG-relative inode offsets for each allocated chunk
        """
        chunks = []
        sb = self.superblock

        # Guard against infinite recursion in corrupted trees
        if depth > 10:
            self.logger.warning(f"AG {ag_num}: inobt recursion depth exceeded at block {root_block}")
            return chunks

        try:
            abs_offset = self._ag_block_to_abs(ag_num, root_block)
            self.file_handle.seek(abs_offset)
            block_data = self.file_handle.read(sb.blocksize)
        except (OSError, IOError) as e:
            self.logger.debug(f"AG {ag_num}: failed to read inobt block {root_block}: {e}")
            return chunks

        if len(block_data) < 16:
            return chunks

        # Check magic
        magic = struct.unpack('>I', block_data[0:4])[0]

        # Determine header size
        if magic in (0x49414233,):  # 'IAB3' — v5 format
            header_size = 56
        elif magic in (0x49414254,):  # 'IABT' — v4 format
            header_size = 16
        else:
            # Unknown magic — might be an invalid block
            self.logger.debug(f"AG {ag_num}: unexpected inobt magic 0x{magic:08X} at block {root_block}")
            return chunks

        bb_level = struct.unpack('>H', block_data[4:6])[0]
        bb_numrecs = struct.unpack('>H', block_data[6:8])[0]

        if bb_level == 0:
            # Leaf node — records contain inode chunk info
            # Each record: startino(4) + freecount(4) + free(8)
            rec_size = 16
            for i in range(bb_numrecs):
                off = header_size + i * rec_size
                if off + 4 > len(block_data):
                    break
                startino = struct.unpack('>I', block_data[off:off+4])[0]
                chunks.append(startino)
        else:
            # Internal node — pointers to child blocks
            # Keys: startino(4) each, then pointers: agblock(4) each
            keys_start = header_size
            ptrs_start = keys_start + bb_numrecs * 4

            for i in range(bb_numrecs):
                ptr_off = ptrs_start + i * 4
                if ptr_off + 4 > len(block_data):
                    break
                child_block = struct.unpack('>I', block_data[ptr_off:ptr_off+4])[0]
                child_chunks = self._walk_agi_btree(ag_num, child_block, bb_level - 1, depth + 1)
                chunks.extend(child_chunks)


        return chunks

    # --------------------------------------------------------
    # Fragmented Recovery: AGF Free-Space Scanning
    # --------------------------------------------------------

    def _build_free_block_set(self):
        """
        Walk the AGF free-space B+tree (bnobt) for every AG and collect
        all free block ranges. Builds a set of individual free block
        numbers for O(1) lookups during extent integrity checks.
        """
        if not self.ag_headers:
            self.parse_ag_headers()

        sb = self.superblock
        self.free_block_ranges = []

        for ag_num in range(sb.agcount):
            agf, _ = self.ag_headers[ag_num]
            if agf.bno_root == 0:
                continue

            try:
                ranges = self._walk_agf_bnobt(ag_num, agf.bno_root, agf.bno_level)
                # Convert AG-relative block numbers to absolute block numbers
                for ag_block, count in ranges:
                    abs_block = ag_num * sb.agblocks + ag_block
                    self.free_block_ranges.append((abs_block, count))
            except Exception as e:
                self.logger.debug(f"AG {ag_num}: failed to walk bnobt: {e}")

        # Build a set of individual block numbers for fast lookup
        # Only build for reasonably sized free-space maps to avoid memory explosion
        total_free_blocks = sum(count for _, count in self.free_block_ranges)
        if total_free_blocks < 10_000_000:  # <10M blocks (~40GB at 4K blocks)
            self._free_block_set = set()
            for start, count in self.free_block_ranges:
                for b in range(start, start + count):
                    self._free_block_set.add(b)
        else:
            # For very large images, use range-based lookup instead
            self._free_block_set = None

        self.logger.info(
            f"Free-space scan: {len(self.free_block_ranges)} free ranges, "
            f"{total_free_blocks} total free blocks"
        )

    def _walk_agf_bnobt(self, ag_num: int, root_block: int, level: int,
                        depth: int = 0) -> List[Tuple[int, int]]:
        """
        Walk the AGF block-number-ordered free-space B+tree (bnobt).

        Returns:
            List of (ag_relative_block, block_count) free ranges
        """
        ranges = []
        sb = self.superblock

        if depth > 10:
            self.logger.warning(f"AG {ag_num}: bnobt recursion depth exceeded")
            return ranges

        try:
            abs_offset = self._ag_block_to_abs(ag_num, root_block)
            self.file_handle.seek(abs_offset)
            block_data = self.file_handle.read(sb.blocksize)
        except (OSError, IOError) as e:
            self.logger.debug(f"AG {ag_num}: failed to read bnobt block {root_block}: {e}")
            return ranges

        if len(block_data) < 16:
            return ranges

        magic = struct.unpack('>I', block_data[0:4])[0]

        # Determine header size based on magic
        if magic == XFS_ABTB_CRC_MAGIC:
            header_size = 56  # v5 long format
        elif magic == XFS_ABTB_MAGIC:
            header_size = 16  # v4 short format
        else:
            self.logger.debug(
                f"AG {ag_num}: unexpected bnobt magic 0x{magic:08X} at block {root_block}"
            )
            return ranges

        bb_level = struct.unpack('>H', block_data[4:6])[0]
        bb_numrecs = struct.unpack('>H', block_data[6:8])[0]

        if bb_level == 0:
            # Leaf node — records are (startblock:4, blockcount:4) pairs
            for i in range(bb_numrecs):
                off = header_size + i * 8
                if off + 8 > len(block_data):
                    break
                start_block = struct.unpack('>I', block_data[off:off+4])[0]
                block_count = struct.unpack('>I', block_data[off+4:off+8])[0]
                if block_count > 0:
                    ranges.append((start_block, block_count))
        else:
            # Internal node — keys (4 bytes each) then pointers (4 bytes each)
            keys_start = header_size
            ptrs_start = keys_start + bb_numrecs * 4

            for i in range(bb_numrecs):
                ptr_off = ptrs_start + i * 4
                if ptr_off + 4 > len(block_data):
                    break
                child_block = struct.unpack('>I', block_data[ptr_off:ptr_off+4])[0]
                child_ranges = self._walk_agf_bnobt(ag_num, child_block, bb_level - 1, depth + 1)
                ranges.extend(child_ranges)

        return ranges

    def _is_block_free(self, abs_block: int) -> bool:
        """Check if a single absolute block number is in the free-space set."""
        if self._free_block_set is not None:
            return abs_block in self._free_block_set

        # Fallback: range-based binary search
        for start, count in self.free_block_ranges:
            if start <= abs_block < start + count:
                return True
        return False

    def _is_extent_likely_intact(self, extent: XfsExtent) -> bool:
        """
        Check if an extent's blocks are currently free (good for recovery)
        or in-use by another file (possibly overwritten).

        Returns True if the extent is in free space (likely intact).
        Returns False if it appears to be in-use (possibly overwritten).
        """
        # Check the first and last block of the extent
        first_free = self._is_block_free(extent.startblock)
        last_block = extent.startblock + extent.blockcount - 1
        last_free = self._is_block_free(last_block)

        if first_free and last_free:
            self.fragmented_recovery_stats['extents_in_free_space'] += 1
            return True
        else:
            self.fragmented_recovery_stats['extents_possibly_overwritten'] += 1
            return False

    # --------------------------------------------------------
    # Fragmented Recovery: AGI Unlinked Inode List
    # --------------------------------------------------------

    def _scan_unlinked_inodes(self):
        """
        Scan the AGI unlinked inode hash table for recently-deleted inodes.

        XFS maintains 64 hash buckets in the AGI header (starting at offset 72).
        Each bucket is the head of a linked list of unlinked inodes. The chain
        is formed via di_next_unlinked at byte offset 16 in each inode's core.
        These inodes are between unlink() and the final inode free, so they
        often still have valid extent data.
        """
        if not self.ag_headers:
            self.parse_ag_headers()

        sb = self.superblock
        unlinked_found = 0

        for ag_num in range(sb.agcount):
            _, agi = self.ag_headers[ag_num]
            ag_offset = self.offset + ag_num * sb.agblocks * sb.blocksize

            # Read the unlinked hash buckets from the AGI
            try:
                agi_offset = ag_offset + 2 * sb.sectsize
                self.file_handle.seek(agi_offset + XFS_AGI_UNLINKED_OFFSET)
                bucket_data = self.file_handle.read(XFS_AGI_UNLINKED_BUCKETS * 4)

                if len(bucket_data) < XFS_AGI_UNLINKED_BUCKETS * 4:
                    continue
            except (OSError, IOError):
                continue

            inodes_per_ag = sb.agblocks * sb.inopblock

            for bucket_idx in range(XFS_AGI_UNLINKED_BUCKETS):
                head_ino = struct.unpack('>I',
                    bucket_data[bucket_idx*4:(bucket_idx+1)*4])[0]

                if head_ino == NULLAGINO or head_ino == 0:
                    continue

                # Follow the unlinked chain
                current_ag_ino = head_ino
                visited = set()
                chain_depth = 0

                while (current_ag_ino != NULLAGINO and current_ag_ino != 0
                       and current_ag_ino not in visited and chain_depth < 1000):
                    visited.add(current_ag_ino)
                    chain_depth += 1

                    abs_ino = ag_num * inodes_per_ag + current_ag_ino

                    # Skip if already in cache
                    if abs_ino not in self.inode_cache:
                        try:
                            abs_offset = self._inode_abs_offset(abs_ino)
                            if abs_offset < 0:
                                break

                            self.file_handle.seek(abs_offset)
                            raw_inode = self.file_handle.read(sb.inodesize)
                            if len(raw_inode) < sb.inodesize:
                                break

                            core = self._parse_inode_core(raw_inode, 0)
                            if core is not None:
                                self.inode_cache[abs_ino] = core

                                # Read extents
                                if core.di_nextents > 0 or core.di_format in (
                                    XFS_DINODE_FMT_EXTENTS, XFS_DINODE_FMT_BTREE
                                ):
                                    exts = self._read_extents_from_inode(raw_inode, core)
                                    if exts:
                                        self.extent_cache[abs_ino] = exts

                                # Try speculative salvage if no extents found
                                if abs_ino not in self.extent_cache:
                                    salvaged = self._try_salvage_extents_for_inode(
                                        raw_inode, core
                                    )
                                    if salvaged:
                                        self.extent_cache[abs_ino] = salvaged

                                unlinked_found += 1
                                self.logger.debug(
                                    f"Unlinked inode {abs_ino} in AG {ag_num} "
                                    f"bucket {bucket_idx}: nblocks={core.di_nblocks}"
                                )
                        except Exception as e:
                            self.logger.debug(
                                f"Error reading unlinked inode {abs_ino}: {e}"
                            )
                            break

                    # Follow chain: di_next_unlinked is at offset 16 in inode core
                    try:
                        abs_offset = self._inode_abs_offset(abs_ino)
                        self.file_handle.seek(abs_offset + 16)
                        next_data = self.file_handle.read(4)
                        if len(next_data) < 4:
                            break
                        current_ag_ino = struct.unpack('>I', next_data)[0]
                    except Exception:
                        break

        self.fragmented_recovery_stats['unlinked_inodes_found'] = unlinked_found
        self.logger.info(
            f"Unlinked inode scan: found {unlinked_found} inodes in AGI unlinked lists"
        )

    # --------------------------------------------------------
    # Fragmented Recovery: Speculative Extent Salvage
    # --------------------------------------------------------

    def _try_salvage_extents_for_inode(self, inode_data: bytes,
                                       inode_core: XfsInodeCore) -> List[XfsExtent]:
        """
        Attempt to salvage extent records from a deleted inode whose
        di_nextents has been zeroed but whose data fork bytes may still
        contain valid 128-bit extent records.

        This is the speculative recovery path for heavily-cleared inodes.
        Only activated for inodes that appear deleted but have no extents
        from the normal parsing path.

        Args:
            inode_data: Complete raw inode data
            inode_core: Parsed inode core

        Returns:
            List of plausible extent records, or empty list
        """
        # Only attempt on likely-deleted inodes with block count but no extents
        if inode_core.di_nextents > 0:
            return []  # Normal path should have handled this

        if inode_core.di_nblocks == 0:
            return []  # No data to recover

        # Determine data fork boundaries
        if inode_core.di_version == 3:
            data_fork_offset = XFS_DINODE_CORE_V3_SIZE
        else:
            data_fork_offset = XFS_DINODE_CORE_V2_SIZE

        if inode_core.di_forkoff > 0:
            data_fork_size = inode_core.di_forkoff * 8
        else:
            data_fork_size = len(inode_data) - data_fork_offset

        # Quick check: is the data fork all zeros?
        fork_bytes = inode_data[data_fork_offset:data_fork_offset + data_fork_size]
        if fork_bytes == b'\x00' * len(fork_bytes):
            return []  # Completely zeroed — nothing to salvage

        salvaged = self._try_salvage_extents(inode_data, data_fork_offset, data_fork_size)

        if salvaged:
            self.fragmented_recovery_stats['salvaged_extent_inodes'] += 1
            self.logger.info(
                f"Salvaged {len(salvaged)} extents from zeroed-count inode "
                f"(nblocks={inode_core.di_nblocks})"
            )

        return salvaged

    def _try_salvage_extents(self, inode_data: bytes, fork_offset: int,
                             fork_size: int) -> List[XfsExtent]:
        """
        Speculatively parse 16-byte extent records from a data fork whose
        extent count was zeroed by deletion.

        Applies strict sanity checks to avoid false positives:
        - startblock must be > 0 and within filesystem bounds
        - blockcount must be > 0 and < 2^21 (XFS max)
        - startoff must have reasonable logical offset
        - No duplicate or overlapping extents
        """
        extents = []
        sb = self.superblock
        if not sb:
            return extents

        max_blocks = sb.dblocks  # Total filesystem blocks
        max_extent_blocks = (1 << 21) - 1  # 2,097,151 blocks

        max_extents = fork_size // 16
        seen_blocks = set()

        for i in range(max_extents):
            off = fork_offset + i * 16
            if off + 16 > len(inode_data):
                break

            try:
                ext = self._decode_extent(inode_data, off)
            except Exception:
                continue

            # Strict validation
            if ext.blockcount == 0 or ext.startblock == 0:
                continue
            if ext.blockcount > max_extent_blocks:
                continue
            if ext.startblock >= max_blocks:
                continue
            if ext.startoff > 1_000_000_000:  # Unreasonable logical offset
                continue

            # Check for overlapping block ranges
            block_range = range(ext.startblock, ext.startblock + ext.blockcount)
            if any(b in seen_blocks for b in [block_range.start, block_range.stop - 1]):
                continue

            seen_blocks.add(block_range.start)
            seen_blocks.add(block_range.stop - 1)
            extents.append(ext)

        return extents

    # --------------------------------------------------------
    # Fragmented Recovery: Confidence Scoring
    # --------------------------------------------------------

    def _compute_recovery_confidence(self, inode_num: int,
                                      file_data: bytes) -> Tuple[float, str]:
        """
        Evaluate the quality/confidence of a recovered file.

        Scoring factors:
        - Extent free-space status: are the data blocks still free (not reallocated)?
        - Extent contiguity: are logical offsets contiguous or heavily gapped?
        - File structure: did _detect_true_file_size find a valid structure?
        - Data entropy: does the data look like a real file (not all zeros)?

        Returns:
            (confidence: float 0.0-1.0, detail_string: str)
        """
        details = []
        scores = []

        extents = self.extent_cache.get(inode_num, [])

        # 1. Free-space check (weight: 40%)
        if extents and self.free_block_ranges:
            intact_count = 0
            total_count = len(extents)
            for ext in extents:
                if self._is_extent_likely_intact(ext):
                    intact_count += 1

            free_ratio = intact_count / total_count if total_count > 0 else 0
            scores.append(('free_space', free_ratio, 0.40))

            if free_ratio >= 0.9:
                details.append(f"blocks in free space: {intact_count}/{total_count} (excellent)")
            elif free_ratio >= 0.5:
                details.append(f"blocks in free space: {intact_count}/{total_count} (partial)")
            else:
                details.append(f"blocks in free space: {intact_count}/{total_count} (low - may be overwritten)")
        else:
            scores.append(('free_space', 0.5, 0.40))  # Unknown = neutral
            details.append("free-space status: unknown (no AGF data)")

        # 2. Extent contiguity (weight: 20%)
        if len(extents) > 1:
            sorted_exts = sorted(extents, key=lambda e: e.startoff)
            gaps = 0
            for j in range(1, len(sorted_exts)):
                expected = sorted_exts[j-1].startoff + sorted_exts[j-1].blockcount
                if sorted_exts[j].startoff != expected:
                    gaps += 1
            gap_ratio = 1.0 - (gaps / (len(sorted_exts) - 1))
            scores.append(('contiguity', max(0, gap_ratio), 0.20))
            if gaps > 0:
                details.append(f"extent gaps: {gaps} (fragmented)")
            else:
                details.append("extents: contiguous")
        elif len(extents) == 1:
            scores.append(('contiguity', 1.0, 0.20))
            details.append("extents: single extent (contiguous)")
        else:
            scores.append(('contiguity', 0.0, 0.20))
            details.append("extents: none found")

        # 3. File structure detection (weight: 25%)
        if file_data and len(file_data) > 8:
            detected_size = self._detect_true_file_size(file_data)
            if detected_size < len(file_data):
                # Valid structure found — high confidence
                scores.append(('structure', 1.0, 0.25))
                details.append(f"file structure: valid (detected size: {detected_size})")
            else:
                scores.append(('structure', 0.5, 0.25))
                details.append("file structure: no recognized format header")
        else:
            scores.append(('structure', 0.0, 0.25))
            details.append("file structure: no data")

        # 4. Data quality (weight: 15%)
        if file_data and len(file_data) > 0:
            # Check if data is all zeros (garbage)
            sample_size = min(4096, len(file_data))
            sample = file_data[:sample_size]
            zero_ratio = sample.count(0) / len(sample)
            if zero_ratio > 0.99:
                scores.append(('data_quality', 0.0, 0.15))
                details.append("data quality: all zeros (likely overwritten)")
            elif zero_ratio > 0.8:
                scores.append(('data_quality', 0.3, 0.15))
                details.append("data quality: mostly zeros")
            else:
                scores.append(('data_quality', 1.0, 0.15))
                details.append("data quality: non-trivial content")
        else:
            scores.append(('data_quality', 0.0, 0.15))
            details.append("data quality: no data")

        # Compute weighted score
        confidence = sum(score * weight for _, score, weight in scores)
        confidence = max(0.0, min(1.0, confidence))

        detail_str = "; ".join(details)
        return confidence, detail_str

    # --------------------------------------------------------
    # Deleted File Detection
    # --------------------------------------------------------

    def _is_deleted_inode(self, core: XfsInodeCore) -> bool:
        """
        Detect if an inode represents a deleted file.

        XFS zeroes di_mode and di_size upon deletion, but often
        preserves the extent list. A deleted file has:
        - di_mode == 0 (type cleared)
        - di_nlink == 0 (all links removed)
        - But di_nblocks > 0 or di_nextents > 0 (data still on disk)
        """
        # Classic deletion pattern: mode zeroed but extents remain
        if core.di_mode == 0 and (core.di_nblocks > 0 or core.di_nextents > 0):
            return True

        # Unlinked but mode preserved (less common)
        if core.di_nlink == 0 and core.di_mode != 0 and core.di_nblocks > 0:
            return True

        return False

    def _get_file_type_str(self, mode: int) -> str:
        """Get human-readable file type string from mode."""
        fmt = mode & S_IFMT
        types = {
            S_IFREG: "regular",
            S_IFDIR: "directory",
            S_IFLNK: "symlink",
            S_IFBLK: "block_device",
            S_IFCHR: "char_device",
            S_IFIFO: "fifo",
            S_IFSOCK: "socket",
        }
        return types.get(fmt, "unknown")

    # --------------------------------------------------------
    # File Size Detection for Deleted Files
    # --------------------------------------------------------

    def _detect_true_file_size(self, data: bytes) -> int:
        """
        Detect the true file size from internal file headers/footers.

        When XFS deletes a file, di_size is zeroed but extent data remains.
        The recovered data is block-aligned and includes trailing slack bytes
        that can corrupt formats like PDF and BMP. This method inspects the
        data's internal structure to find the real end-of-file.

        Supports: BMP, PDF, JPG/JPEG, PNG, GIF, ZIP/DOCX/XLSX/ODT, TIFF

        Args:
            data: Raw recovered data (may include trailing slack)

        Returns:
            Detected true file size, or len(data) if unknown
        """
        if len(data) < 8:
            return len(data)

        # --- BMP: file size is stored in the header at bytes 2-5 (LE 32-bit) ---
        if data[:2] == b'BM':
            bmp_size = struct.unpack('<I', data[2:6])[0]
            if 14 < bmp_size <= len(data):
                self.logger.debug(f"BMP header declares size: {bmp_size}")
                return bmp_size

        # --- PDF: find last occurrence of %%EOF ---
        if data[:5] == b'%PDF-':
            # Search backwards for %%EOF (may be followed by \r\n or \n)
            eof_marker = b'%%EOF'
            pos = data.rfind(eof_marker)
            if pos != -1:
                # Include the marker and any trailing newline
                end = pos + len(eof_marker)
                if end < len(data) and data[end:end+1] in (b'\r', b'\n'):
                    end += 1
                if end < len(data) and data[end:end+1] == b'\n':
                    end += 1
                self.logger.debug(f"PDF %%EOF found at offset {pos}, true size: {end}")
                return end

        # --- JPEG: find FFD9 end-of-image marker ---
        if data[:2] == b'\xff\xd8':
            # Search for the last FFD9 marker
            pos = data.rfind(b'\xff\xd9')
            if pos != -1:
                end = pos + 2
                self.logger.debug(f"JPEG EOI marker at offset {pos}, true size: {end}")
                return end

        # --- PNG: find IEND chunk ---
        if data[:8] == b'\x89PNG\r\n\x1a\n':
            iend_marker = b'IEND'
            pos = data.rfind(iend_marker)
            if pos != -1:
                # IEND chunk: 4-byte length (0) + 'IEND' + 4-byte CRC
                # The length field is 4 bytes before 'IEND'
                end = pos + 4 + 4  # 'IEND' + CRC32
                self.logger.debug(f"PNG IEND at offset {pos}, true size: {end}")
                return end

        # --- GIF: ends with trailer byte 0x3B ---
        if data[:4] in (b'GIF8',):
            pos = data.rfind(b'\x3b')
            if pos > 6:
                end = pos + 1
                self.logger.debug(f"GIF trailer at offset {pos}, true size: {end}")
                return end

        # --- ZIP / DOCX / XLSX / ODT: find End-of-Central-Directory record ---
        if data[:2] == b'PK':
            eocd_sig = b'PK\x05\x06'
            pos = data.rfind(eocd_sig)
            if pos != -1:
                # EOCD is at least 22 bytes; last 2 bytes = comment length
                if pos + 22 <= len(data):
                    comment_len = struct.unpack('<H', data[pos+20:pos+22])[0]
                    end = pos + 22 + comment_len
                    if end <= len(data):
                        self.logger.debug(f"ZIP EOCD at offset {pos}, true size: {end}")
                        return end

        # --- TIFF: parse IFD chain to find furthest data offset ---
        if data[:4] in (b'II\x2a\x00', b'MM\x00\x2a'):
            return self._detect_tiff_size(data)

        # Unknown format — strip trailing null bytes as a best-effort trim
        # This helps with text files and many other formats
        end = len(data)
        while end > 0 and data[end - 1:end] == b'\x00':
            end -= 1
        if end < len(data):
            # Don't trim more than the last block worth of nulls
            # (could be legitimate null-filled data in binary files)
            sb = self.superblock
            max_trim = sb.blocksize if sb else 4096
            trimmed = len(data) - end
            if trimmed <= max_trim:
                self.logger.debug(f"Trimmed {trimmed} trailing null bytes")
                return end

        return len(data)

    def _detect_tiff_size(self, data: bytes) -> int:
        """Detect TIFF file size by following IFD chain."""
        if len(data) < 8:
            return len(data)

        # Determine byte order
        if data[:2] == b'II':
            endian = '<'
        else:
            endian = '>'

        max_offset = 8  # Minimum TIFF header

        try:
            # First IFD offset at byte 4
            ifd_offset = struct.unpack(endian + 'I', data[4:8])[0]

            visited = set()
            while ifd_offset != 0 and ifd_offset < len(data) and ifd_offset not in visited:
                visited.add(ifd_offset)
                if ifd_offset + 2 > len(data):
                    break

                num_entries = struct.unpack(endian + 'H', data[ifd_offset:ifd_offset+2])[0]
                ifd_end = ifd_offset + 2 + num_entries * 12 + 4
                max_offset = max(max_offset, ifd_end)

                # Check each IFD entry for data offsets
                for i in range(num_entries):
                    entry_off = ifd_offset + 2 + i * 12
                    if entry_off + 12 > len(data):
                        break
                    value_count = struct.unpack(endian + 'I', data[entry_off+4:entry_off+8])[0]
                    value_offset = struct.unpack(endian + 'I', data[entry_off+8:entry_off+12])[0]
                    # StripOffsets(273) or StripByteCounts(279) or TileOffsets(324)
                    tag = struct.unpack(endian + 'H', data[entry_off:entry_off+2])[0]
                    typ = struct.unpack(endian + 'H', data[entry_off+2:entry_off+4])[0]
                    if tag in (273, 279, 324, 325):  # Strip/tile offset/bytecount tags
                        if value_offset + value_count * 4 < len(data):
                            max_offset = max(max_offset, value_offset + value_count * 4)

                # Next IFD
                next_ifd_off = ifd_offset + 2 + num_entries * 12
                if next_ifd_off + 4 > len(data):
                    break
                ifd_offset = struct.unpack(endian + 'I', data[next_ifd_off:next_ifd_off+4])[0]

        except Exception:
            pass

        return min(max_offset, len(data))

    # --------------------------------------------------------
    # File Recovery
    # --------------------------------------------------------

    def recover_file_data(self, inode_num: int) -> Optional[bytes]:
        """
        Recover file data by reading its extents from disk.

        Args:
            inode_num: Inode number to recover

        Returns:
            Recovered file data as bytes, or None on failure
        """
        extents = self.extent_cache.get(inode_num, [])
        if not extents:
            return None

        sb = self.superblock
        core = self.inode_cache.get(inode_num)

        # Sort extents by logical offset
        sorted_extents = sorted(extents, key=lambda e: e.startoff)

        data_parts = []
        expected_offset = 0

        for ext in sorted_extents:
            # Fill gaps with zeros (sparse file support)
            if ext.startoff > expected_offset:
                gap_blocks = ext.startoff - expected_offset
                data_parts.append(b'\x00' * gap_blocks * sb.blocksize)

            # Read extent data from disk
            byte_offset = self._abs_block_to_bytes(ext.startblock)
            read_size = ext.blockcount * sb.blocksize

            try:
                self.file_handle.seek(byte_offset)
                ext_data = self.file_handle.read(read_size)
                data_parts.append(ext_data)
            except Exception as e:
                self.logger.error(f"Failed to read extent at block {ext.startblock}: {e}")
                data_parts.append(b'\x00' * read_size)

            expected_offset = ext.startoff + ext.blockcount

        full_data = b''.join(data_parts)

        # Truncate to file size if known
        if core and core.di_size > 0:
            full_data = full_data[:core.di_size]
        elif core and core.di_size == 0 and core.di_nblocks > 0:
            # Deleted file: di_size zeroed by XFS. Use smart size detection
            # to find the true end-of-file from internal file structure.
            true_size = self._detect_true_file_size(full_data)
            if true_size < len(full_data):
                self.logger.info(
                    f"Inode {inode_num}: trimmed deleted file from "
                    f"{len(full_data)} to {true_size} bytes (detected from file structure)"
                )
                full_data = full_data[:true_size]

        return full_data

    def recover_deleted_files(self, output_dir: str, file_filter: str = "all") -> List[Dict]:
        """
        Recover files from the XFS filesystem and write to output directory.

        This is the main entry point, with the same signature and return format
        as BtrfsParser.recover_deleted_files().

        Args:
            output_dir: Directory to save recovered files
            file_filter: 'all', 'deleted_only', or 'active_only'

        Returns:
            List of recovered file metadata dicts
        """
        if file_filter not in ("all", "deleted_only", "active_only"):
            raise ValueError(f"Invalid file_filter: {file_filter}")

        recovered_files = []
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Reset verification stats
        self.verification_stats = {
            'verified': 0, 'corrupted': 0,
            'unverified': 0, 'no_checksum': 0
        }

        try:
            if not self.file_handle:
                self.open()

            if not self.detect_filesystem():
                raise ValueError("Not a valid XFS filesystem")

            self.parse_superblock()
            self.logger.info("Starting full device scan...")
            self.scan_all_inodes()

            # Fragmented recovery: scan AGI unlinked inode lists
            # for recently-deleted inodes missed by the B+tree walk
            self.logger.info("Scanning AGI unlinked inode lists...")
            self._scan_unlinked_inodes()

            # Build free-space block map for integrity/confidence checking
            self.logger.info("Building free-space block map...")
            self._build_free_block_set()

            self.logger.info(
                f"Fragmented recovery stats: "
                f"{self.fragmented_recovery_stats['unlinked_inodes_found']} unlinked inodes, "
                f"{self.fragmented_recovery_stats['salvaged_extent_inodes']} salvaged-extent inodes"
            )

            count = 0
            skipped_by_filter = 0
            skipped_not_regular = 0
            total_checked = 0

            for inode_num, core in self.inode_cache.items():
                total_checked += 1

                # Only recover regular files
                file_type_bits = core.di_mode & S_IFMT
                is_regular = (file_type_bits == S_IFREG)
                is_deleted = self._is_deleted_inode(core)

                # For deleted inodes, di_mode is zeroed so we can't check type.
                # Recover if they have extents (likely files).
                if not is_regular and not is_deleted:
                    skipped_not_regular += 1
                    continue

                # Skip inodes with no recoverable data
                if inode_num not in self.extent_cache or not self.extent_cache[inode_num]:
                    if core.di_format == XFS_DINODE_FMT_LOCAL and core.di_size > 0:
                        pass  # Inline data, handled below
                    else:
                        skipped_not_regular += 1
                        continue

                # For active files, skip zero-size
                if not is_deleted and core.di_size == 0:
                    skipped_not_regular += 1
                    continue

                file_status = "deleted" if is_deleted else "active"

                # Apply filter
                if file_filter == "deleted_only" and not is_deleted:
                    skipped_by_filter += 1
                    continue
                elif file_filter == "active_only" and is_deleted:
                    skipped_by_filter += 1
                    continue

                # Recover file data
                file_data = self.recover_file_data(inode_num)
                if file_data is None or len(file_data) == 0:
                    continue

                # Determine filename
                original_name = self.name_cache.get(inode_num, f"file_{inode_num}")
                safe_name = "".join(
                    c for c in original_name if c.isalnum() or c in ('._-')
                ).strip()
                if not safe_name:
                    safe_name = f"file_{inode_num}"

                # Prefix with status
                if is_deleted:
                    prefixed_name = f"DELETED_{safe_name}"
                else:
                    prefixed_name = f"ACTIVE_{safe_name}"

                # Handle duplicates
                target_file = out_path / prefixed_name
                counter = 1
                while target_file.exists():
                    target_file = out_path / f"{prefixed_name}_{counter}"
                    counter += 1

                try:
                    # Write recovered data
                    with open(target_file, 'wb') as f:
                        f.write(file_data)

                    # Compute SHA256 hash
                    file_hash = hashlib.sha256(file_data).hexdigest()

                    # Integrity assessment
                    integrity_status = "unverified"
                    integrity_details = "XFS does not store per-file checksums"
                    self.verification_stats['no_checksum'] += 1

                    # Timestamps
                    try:
                        atime = datetime.fromtimestamp(core.di_atime) if core.di_atime > 0 else datetime(1970, 1, 1)
                        mtime = datetime.fromtimestamp(core.di_mtime) if core.di_mtime > 0 else datetime(1970, 1, 1)
                        ctime = datetime.fromtimestamp(core.di_ctime) if core.di_ctime > 0 else datetime(1970, 1, 1)
                    except (ValueError, OSError, OverflowError):
                        atime = mtime = ctime = datetime(1970, 1, 1)

                    recovered_files.append({
                        'name': target_file.name,
                        'original_name': safe_name,
                        'inode': inode_num,
                        'size': len(file_data),
                        'type': self._get_file_type_str(core.di_mode) if core.di_mode else 'unknown',
                        'mode': oct(core.di_mode) if core.di_mode else '0o0',
                        'uid': core.di_uid,
                        'gid': core.di_gid,
                        'modified': mtime.strftime('%Y-%m-%d %H:%M:%S'),
                        'accessed': atime.strftime('%Y-%m-%d %H:%M:%S'),
                        'changed': ctime.strftime('%Y-%m-%d %H:%M:%S'),
                        'hash': file_hash,
                        'status': file_status,
                        'deleted': is_deleted,
                        'nlink': core.di_nlink,
                        'generation': core.di_gen,
                        'extents': len(self.extent_cache.get(inode_num, [])),
                        'path': str(target_file),
                        'integrity_status': integrity_status,
                        'integrity_verified': False,
                        'integrity_details': integrity_details,
                    })

                    # Compute recovery confidence for deleted files
                    if is_deleted:
                        confidence, conf_details = self._compute_recovery_confidence(
                            inode_num, file_data
                        )
                        recovered_files[-1]['recovery_confidence'] = round(confidence, 3)
                        recovered_files[-1]['recovery_details'] = conf_details

                    count += 1

                except Exception as e:
                    self.logger.error(f"Failed to write file inode {inode_num}: {e}")

            self.logger.info(f"Recovery complete: {count} files recovered to {output_dir}")
            self.logger.info(
                f"Inode stats: {total_checked} checked, "
                f"{skipped_not_regular} skipped (not regular), "
                f"{skipped_by_filter} skipped by filter, "
                f"{count} recovered"
            )

        except Exception as e:
            self.logger.error(f"File recovery failed: {e}")
            import traceback
            self.logger.error(traceback.format_exc())

        return recovered_files

    # --------------------------------------------------------
    # Filesystem Info
    # --------------------------------------------------------

    def get_filesystem_info(self) -> Dict:
        """
        Get filesystem metadata.

        Returns:
            Dictionary with filesystem information
        """
        if not self.superblock:
            return {"type": "xfs", "status": "not_parsed"}

        sb = self.superblock
        return {
            "type": "xfs",
            "label": sb.fname,
            "uuid": sb.uuid.hex(),
            "block_size": sb.blocksize,
            "total_blocks": sb.dblocks,
            "total_size": sb.dblocks * sb.blocksize,
            "total_size_human": self._format_size(sb.dblocks * sb.blocksize),
            "free_blocks": sb.sb_fdblocks,
            "free_size": sb.sb_fdblocks * sb.blocksize,
            "ag_count": sb.agcount,
            "ag_blocks": sb.agblocks,
            "inode_size": sb.inodesize,
            "inodes_per_block": sb.inopblock,
            "total_inodes": sb.sb_icount,
            "free_inodes": sb.sb_ifree,
            "sector_size": sb.sectsize,
            "root_inode": sb.rootino,
        }

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format byte size to human-readable string."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"


# ============================================================
# Example Usage
# ============================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python xfs_parser.py <disk_image> [output_dir]")
        sys.exit(1)

    image_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "/tmp/xfs_recovered"

    with XfsParser(image_path) as parser:
        if parser.detect_filesystem():
            print("✓ XFS filesystem detected")
            sb = parser.parse_superblock()
            print(f"  Block size: {sb.blocksize}")
            print(f"  AG count:   {sb.agcount}")
            print(f"  Inode size: {sb.inodesize}")

            files = parser.recover_deleted_files(output_dir)
            print(f"\n  Recovered {len(files)} files to {output_dir}")
            for f in files[:20]:
                print(f"  - {f['name']} ({f['size']} bytes, status={f['status']})")
        else:
            print("✗ Not an XFS filesystem")
