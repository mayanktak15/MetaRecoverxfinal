"""
Unearth Utility Functions
Includes partition detection, filesystem utilities, and helper functions

Dependencies:
    pip install psutil
"""

import os
import sys
import hashlib
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
import psutil
import struct


class PartitionDetector:
    """Detect and list XFS/Btrfs partitions on the system"""
    
    @staticmethod
    def get_all_partitions() -> List[Dict]:
        """
        Get all disk partitions on the system (including unmounted ones)
        
        Returns:
            List of partition info dictionaries
        """
        partitions = []
        seen_devices = set()
        
        try:
            # First get mounted partitions from psutil
            for partition in psutil.disk_partitions(all=True):
                part_info = {
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'opts': partition.opts,
                    'mounted': True,
                }
                
                # Get usage info if mounted
                try:
                    usage = psutil.disk_usage(partition.mountpoint)
                    part_info['total'] = usage.total
                    part_info['used'] = usage.used
                    part_info['free'] = usage.free
                    part_info['percent'] = usage.percent
                except (PermissionError, OSError):
                    part_info['total'] = 0
                    part_info['used'] = 0
                    part_info['free'] = 0
                    part_info['percent'] = 0
                
                partitions.append(part_info)
                seen_devices.add(partition.device)
            
            # Now detect unmounted partitions using lsblk
            try:
                import subprocess
                result = subprocess.run(
                    ['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID'],
                    capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    import json
                    data = json.loads(result.stdout)
                    
                    def process_device(dev, parent_name=None):
                        dev_name = dev.get('name', '')
                        dev_path = f"/dev/{dev_name}"
                        dev_type = dev.get('type', '')
                        fstype = dev.get('fstype', '') or ''
                        mountpoint = dev.get('mountpoint', '') or ''
                        
                        # Only process partitions (not whole disks)
                        if dev_type == 'part' and dev_path not in seen_devices:
                            # This is an unmounted partition
                            part_info = {
                                'device': dev_path,
                                'mountpoint': mountpoint if mountpoint else '(not mounted)',
                                'fstype': fstype,
                                'opts': '',
                                'mounted': False,
                                'label': dev.get('label', ''),
                                'uuid': dev.get('uuid', ''),
                                'size_str': dev.get('size', ''),
                            }
                            
                            # Parse size from lsblk format (e.g., "14.9G")
                            size_str = dev.get('size', '0')
                            try:
                                if 'G' in size_str:
                                    part_info['total'] = int(float(size_str.replace('G', '')) * 1024**3)
                                elif 'M' in size_str:
                                    part_info['total'] = int(float(size_str.replace('M', '')) * 1024**2)
                                elif 'T' in size_str:
                                    part_info['total'] = int(float(size_str.replace('T', '')) * 1024**4)
                                else:
                                    part_info['total'] = 0
                            except ValueError:
                                part_info['total'] = 0
                            
                            part_info['used'] = 0
                            part_info['free'] = part_info['total']
                            part_info['percent'] = 0
                            
                            partitions.append(part_info)
                            seen_devices.add(dev_path)
                        
                        # Process children (partitions of the disk)
                        for child in dev.get('children', []):
                            process_device(child, dev_name)
                    
                    for device in data.get('blockdevices', []):
                        process_device(device)
                        
            except (subprocess.TimeoutExpired, FileNotFoundError, json.JSONDecodeError) as e:
                # lsblk not available or failed, continue with mounted partitions only
                pass
                
        except Exception as e:
            print(f"Error detecting partitions: {e}")
        
        return partitions
    
    @staticmethod
    def filter_xfs_btrfs_partitions(partitions: List[Dict]) -> List[Dict]:
        """
        Filter partitions to only XFS and Btrfs types
        
        Args:
            partitions: List of all partitions
            
        Returns:
            Filtered list containing only XFS/Btrfs partitions
        """
        supported_fs = ['xfs', 'btrfs']
        return [
            p for p in partitions 
            if p['fstype'].lower() in supported_fs
        ]
    
    @staticmethod
    def detect_filesystem_type(device_path: str) -> Optional[str]:
        """
        Detect filesystem type by reading magic numbers
        
        Args:
            device_path: Path to device or image file
        
        Returns:
            Filesystem type ('xfs', 'btrfs', 'unknown')
        """
        # Try using Btrfs parser for accurate detection
        try:
            from core.btrfs_parser import BtrfsParser
            parser = BtrfsParser(device_path)
            with parser:
                if parser.detect_filesystem():
                    return 'btrfs'
        except Exception:
            pass  # Fall back to manual detection
    
        # Manual magic number detection
        try:
            with open(device_path, 'rb') as f:
                # Check XFS magic (XFSB at offset 0)
                f.seek(0)
                magic = f.read(4)
                if magic == b'XFSB':
                    return 'xfs'
                
                # Check Btrfs magic (_BHRfS_M at offset 0x10040)
                f.seek(0x10040)
                magic = f.read(8)
                if magic == b'_BHRfS_M':
                    return 'btrfs'
            
        except (IOError, PermissionError) as e:
            print(f"Cannot read device {device_path}: {e}")
    
        return 'unknown'
    
    @staticmethod
    def get_external_drives() -> List[Dict]:
        """
        Detect external/removable drives (USB, etc.)
        
        Returns:
            List of external drive info
        """
        external = []
        
        if sys.platform.startswith('linux'):
            # Linux: Check /sys/block for removable devices
            try:
                for device in Path('/sys/block').iterdir():
                    removable_path = device / 'removable'
                    if removable_path.exists():
                        with open(removable_path, 'r') as f:
                            if f.read().strip() == '1':
                                device_path = f'/dev/{device.name}'
                                
                                # Get partitions for this device
                                for partition in psutil.disk_partitions():
                                    if partition.device.startswith(device_path):
                                        external.append({
                                            'device': partition.device,
                                            'mountpoint': partition.mountpoint,
                                            'fstype': partition.fstype,
                                            'removable': True
                                        })
            except Exception as e:
                print(f"Error detecting external drives: {e}")
        
        elif sys.platform == 'win32':
            # Windows: Check drive types
            import win32api
            import win32file
            
            try:
                drives = win32api.GetLogicalDriveStrings()
                drives = drives.split('\000')[:-1]
                
                for drive in drives:
                    drive_type = win32file.GetDriveType(drive)
                    # DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3
                    if drive_type == 2:  # Removable
                        for partition in psutil.disk_partitions():
                            if partition.device.startswith(drive):
                                external.append({
                                    'device': partition.device,
                                    'mountpoint': partition.mountpoint,
                                    'fstype': partition.fstype,
                                    'removable': True
                                })
            except Exception as e:
                print(f"Error detecting external drives: {e}")
        
        elif sys.platform == 'darwin':
            # macOS: Check for external volumes
            try:
                result = subprocess.run(
                    ['diskutil', 'list', '-plist'],
                    capture_output=True,
                    text=True
                )
                # Parse diskutil output to find external drives
                # Simplified for now
                for partition in psutil.disk_partitions():
                    if '/Volumes/' in partition.mountpoint:
                        external.append({
                            'device': partition.device,
                            'mountpoint': partition.mountpoint,
                            'fstype': partition.fstype,
                            'removable': True
                        })
            except Exception as e:
                print(f"Error detecting external drives: {e}")
        
        return external
    
    @staticmethod
    def format_size(bytes_size: int) -> str:
        """
        Format byte size to human-readable format
        
        Args:
            bytes_size: Size in bytes
            
        Returns:
            Formatted string (e.g., "1.5 GB")
        """
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.1f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.1f} PB"


class FileHasher:
    """Compute cryptographic hashes for files"""
    
    @staticmethod
    def compute_hash(file_path: str, algorithm: str = 'sha256', chunk_size: int = 8192) -> str:
        """
        Compute hash of a file
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256')
            chunk_size: Chunk size for reading file
            
        Returns:
            Hex string of hash
        """
        if algorithm == 'md5':
            hasher = hashlib.md5()
        elif algorithm == 'sha1':
            hasher = hashlib.sha1()
        elif algorithm == 'sha256':
            hasher = hashlib.sha256()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            print(f"Error hashing file {file_path}: {e}")
            return ""
    
    @staticmethod
    def verify_hash(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
        """
        Verify file hash matches expected value
        
        Args:
            file_path: Path to file
            expected_hash: Expected hash value
            algorithm: Hash algorithm
            
        Returns:
            True if hash matches, False otherwise
        """
        computed = FileHasher.compute_hash(file_path, algorithm)
        return computed.lower() == expected_hash.lower()


class FileTypeDetector:
    """Detect file types based on magic numbers"""
    
    # File signatures (magic numbers)
    SIGNATURES = {
        # Images
        'jpg': [(0, b'\xFF\xD8\xFF')],
        'png': [(0, b'\x89PNG\r\n\x1a\n')],
        'gif': [(0, b'GIF87a'), (0, b'GIF89a')],
        'bmp': [(0, b'BM')],
        'tiff': [(0, b'II*\x00'), (0, b'MM\x00*')],
        
        # Documents
        'pdf': [(0, b'%PDF')],
        'docx': [(0, b'PK\x03\x04'), (30, b'word/')],
        'xlsx': [(0, b'PK\x03\x04'), (30, b'xl/')],
        'pptx': [(0, b'PK\x03\x04'), (30, b'ppt/')],
        
        # Archives
        'zip': [(0, b'PK\x03\x04'), (0, b'PK\x05\x06'), (0, b'PK\x07\x08')],
        'rar': [(0, b'Rar!\x1a\x07')],
        '7z': [(0, b'7z\xbc\xaf\x27\x1c')],
        'tar': [(257, b'ustar')],
        'gz': [(0, b'\x1f\x8b')],
        
        # Video
        'mp4': [(4, b'ftyp')],
        'avi': [(0, b'RIFF'), (8, b'AVI ')],
        'mkv': [(0, b'\x1a\x45\xdf\xa3')],
        'mov': [(4, b'ftyp'), (4, b'moov')],
        
        # Audio
        'mp3': [(0, b'ID3'), (0, b'\xff\xfb')],
        'wav': [(0, b'RIFF'), (8, b'WAVE')],
        'flac': [(0, b'fLaC')],
        
        # Executables
        'exe': [(0, b'MZ')],
        'elf': [(0, b'\x7fELF')],
    }
    
    @classmethod
    def detect_type(cls, file_path: str) -> Optional[str]:
        """
        Detect file type based on magic numbers
        
        Args:
            file_path: Path to file
            
        Returns:
            File type extension or None
        """
        try:
            with open(file_path, 'rb') as f:
                header = f.read(512)  # Read first 512 bytes
                
                for file_type, signatures in cls.SIGNATURES.items():
                    for offset, magic in signatures:
                        if len(header) > offset + len(magic):
                            if header[offset:offset + len(magic)] == magic:
                                return file_type
        except Exception as e:
            print(f"Error detecting file type: {e}")
        
        return None
    
    @classmethod
    def get_category(cls, file_type: str) -> str:
        """
        Get category for file type
        
        Args:
            file_type: File extension
            
        Returns:
            Category name
        """
        categories = {
            'Pictures': ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'raw', 'svg'],
            'Video': ['mp4', 'avi', 'mkv', 'mov', 'wmv', 'flv', 'webm'],
            'Audio': ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'wma'],
            'Documents': ['pdf', 'doc', 'docx', 'txt', 'xlsx', 'pptx', 'odt', 'rtf'],
            'Archives': ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'xz'],
            'Executables': ['exe', 'dll', 'so', 'elf', 'app', 'dmg'],
        }
        
        for category, extensions in categories.items():
            if file_type.lower() in extensions:
                return category
        
        return 'Other'


class MetadataExtractor:
    """Extract metadata from files"""
    
    @staticmethod
    def extract_basic_metadata(file_path: str) -> Dict:
        """
        Extract basic filesystem metadata
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary of metadata
        """
        metadata = {}
        
        try:
            path = Path(file_path)
            stat = path.stat()
            
            metadata['name'] = path.name
            metadata['size'] = stat.st_size
            metadata['created'] = stat.st_ctime
            metadata['modified'] = stat.st_mtime
            metadata['accessed'] = stat.st_atime
            metadata['permissions'] = oct(stat.st_mode)[-3:]
            metadata['inode'] = stat.st_ino
            metadata['uid'] = stat.st_uid
            metadata['gid'] = stat.st_gid
            
        except Exception as e:
            print(f"Error extracting metadata from {file_path}: {e}")
        
        return metadata
    
    @staticmethod
    def extract_exif_metadata(file_path: str) -> Dict:
        """
        Extract EXIF metadata from images (requires PIL/Pillow)
        
        Args:
            file_path: Path to image file
            
        Returns:
            Dictionary of EXIF data
        """
        exif_data = {}
        
        try:
            from PIL import Image
            from PIL.ExifTags import TAGS
            
            image = Image.open(file_path)
            exif = image.getexif()
            
            if exif:
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    exif_data[tag] = value
                    
        except ImportError:
            pass  # PIL not available
        except Exception as e:
            print(f"Error extracting EXIF: {e}")
        
        return exif_data


def check_root_permissions() -> bool:
    """
    Check if running with root/admin permissions
    
    Returns:
        True if has permissions, False otherwise
    """
    if sys.platform.startswith('linux') or sys.platform == 'darwin':
        return os.geteuid() == 0
    elif sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    return False


def request_root_permissions():
    """Request root/admin permissions if not already elevated"""
    if not check_root_permissions():
        print("⚠️  Warning: Root/Administrator permissions required for raw disk access")
        print("Some features may be limited without proper permissions.")
        
        if sys.platform.startswith('linux') or sys.platform == 'darwin':
            print("\nRun with sudo:")
            print(f"  sudo python {' '.join(sys.argv)}")
        elif sys.platform == 'win32':
            print("\nRun as Administrator:")
            print("  Right-click on Command Prompt -> 'Run as Administrator'")


# Convenience functions

def _get_removable_device_names() -> set:
    """Get the set of removable device base names (e.g. {'sdb', 'sdc'})."""
    removable = set()
    if sys.platform.startswith('linux'):
        try:
            for device in Path('/sys/block').iterdir():
                removable_path = device / 'removable'
                if removable_path.exists():
                    with open(removable_path, 'r') as f:
                        if f.read().strip() == '1':
                            removable.add(device.name)  # e.g. 'sdb'
        except Exception:
            pass
    return removable


def list_xfs_btrfs_partitions() -> List[Dict]:
    """List XFS/Btrfs partitions on INTERNAL (non-removable) disks only."""
    detector = PartitionDetector()
    all_partitions = detector.get_all_partitions()
    xfs_btrfs = detector.filter_xfs_btrfs_partitions(all_partitions)
    
    # Exclude removable/external drives — they belong in list_external_drives()
    removable_names = _get_removable_device_names()
    system_only = []
    for p in xfs_btrfs:
        device = p.get('device', '')
        # Check if the partition's parent disk is removable
        # e.g. /dev/sdb1 -> parent disk is 'sdb'
        import re
        match = re.match(r'/dev/(\w+?)(\d+)$', device)
        if match:
            parent_disk = match.group(1)  # e.g. 'sdb'
            if parent_disk in removable_names:
                continue  # Skip — this is an external drive
        system_only.append(p)
    
    return system_only


def list_external_drives() -> List[Dict]:
    """List external/removable drives with XFS or Btrfs filesystems."""
    removable_names = _get_removable_device_names()
    
    if not removable_names:
        return []
    
    # Use lsblk to get detailed info about all partitions on removable disks
    external = []
    try:
        import json as _json
        result = subprocess.run(
            ['lsblk', '-J', '-o', 'NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT,LABEL,UUID'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            data = _json.loads(result.stdout)
            
            for device in data.get('blockdevices', []):
                dev_name = device.get('name', '')
                
                # Only process removable disks and their children
                if dev_name not in removable_names:
                    continue
                
                children = device.get('children', [])
                if not children:
                    # Disk itself may be a partition (no children)
                    children = [device]
                
                for child in children:
                    child_name = child.get('name', '')
                    child_type = child.get('type', '')
                    fstype = child.get('fstype', '') or ''
                    mountpoint = child.get('mountpoint', '') or ''
                    label = child.get('label', '') or ''
                    size_str = child.get('size', '0')
                    
                    if child_type not in ('part', 'disk'):
                        continue
                    
                    # Parse size
                    total = 0
                    try:
                        if 'G' in size_str:
                            total = int(float(size_str.replace('G', '')) * 1024**3)
                        elif 'M' in size_str:
                            total = int(float(size_str.replace('M', '')) * 1024**2)
                        elif 'T' in size_str:
                            total = int(float(size_str.replace('T', '')) * 1024**4)
                    except ValueError:
                        pass
                    
                    external.append({
                        'device': f'/dev/{child_name}',
                        'mountpoint': mountpoint if mountpoint else '(not mounted)',
                        'fstype': fstype,
                        'label': label,
                        'removable': True,
                        'mounted': bool(mountpoint),
                        'total': total,
                        'used': 0,
                        'free': total,
                        'percent': 0,
                    })
    except Exception:
        # Fallback to psutil-based detection
        detector = PartitionDetector()
        return detector.get_external_drives()
    
    return external


def format_bytes(size: int) -> str:
    """Format byte size to human-readable string"""
    return PartitionDetector.format_size(size)


def compute_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """Compute hash of a file"""
    return FileHasher.compute_hash(file_path, algorithm)


def detect_file_type(file_path: str) -> Optional[str]:
    """Detect file type from magic numbers"""
    return FileTypeDetector.detect_type(file_path)


def get_file_category(file_type: str) -> str:
    """Get category for file type"""
    return FileTypeDetector.get_category(file_type)


if __name__ == "__main__":
    # Test partition detection
    print("=== XFS/Btrfs Partitions ===")
    partitions = list_xfs_btrfs_partitions()
    for p in partitions:
        print(f"Device: {p['device']}")
        print(f"  Mount: {p['mountpoint']}")
        print(f"  Type: {p['fstype']}")
        print(f"  Size: {format_bytes(p['total'])}")
        
        # Test filesystem detection with parser
        fs_detected = PartitionDetector.detect_filesystem_type(p['device'])
        print(f"  Detected: {fs_detected}")
        print()
    
    print("=== External Drives ===")
    external = list_external_drives()
    for e in external:
        print(f"Device: {e['device']}")
        print(f"  Mount: {e['mountpoint']}")
        print(f"  Type: {e['fstype']}")
        
        # Test filesystem detection
        fs_detected = PartitionDetector.detect_filesystem_type(e['device'])
        print(f"  Detected: {fs_detected}")
        print()