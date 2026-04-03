import os
import struct
import logging
import hashlib
from pathlib import Path
from typing import List, Dict, Optional, Tuple, Set

from core.metadata_extractor import MetadataExtractor

class FileCarver:
    """
    File Carving Engine.
    Scans raw disk data for magic numbers/signatures to recover files 
    without filesystem metadata. Specifically tuned for COW filesystems
    like Btrfs where recently deleted file metadata may be overwritten
    but data extents often survive.
    """
    
    # Common file signatures — tuned for modern photo/document recovery
    SIGNATURES = {
        'jpg': {
            'header': b'\xFF\xD8\xFF',
            'footer': b'\xFF\xD9',
            'max_size': 50 * 1024 * 1024,  # 50MB — modern phone photos can be 20MB+
            'min_size': 4096,  # Minimum viable JPEG
        },
        'png': {
            'header': b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A',
            'footer': b'\x49\x45\x4E\x44\xAE\x42\x60\x82',
            'max_size': 50 * 1024 * 1024,
            'min_size': 100,
        },
        'pdf': {
            'header': b'%PDF-',
            'footer': b'%%EOF',
            'max_size': 50 * 1024 * 1024,
            'min_size': 100,
        },
        'gif': {
            'header': b'GIF89a',
            'footer': b'\x00\x3B',
            'max_size': 10 * 1024 * 1024,
            'min_size': 50,
        },
        'gif87': {
            'header': b'GIF87a',
            'footer': b'\x00\x3B',
            'max_size': 10 * 1024 * 1024,
            'min_size': 50,
        },
        'zip': {
            'header': b'\x50\x4B\x03\x04',
            'footer': None,
            'max_size': 100 * 1024 * 1024,
            'min_size': 100,
        },
        'mp3_id3': {
            'header': b'ID3',
            'footer': None,
            'max_size': 30 * 1024 * 1024,
            'min_size': 1024,
        },
        'bmp': {
            'header': b'BM',
            'footer': None,
            'max_size': 50 * 1024 * 1024,
            'min_size': 100,
            'validator': '_validate_bmp',
        },
        'tiff': {
            'header': b'\x49\x49\x2A\x00',  # Little-endian TIFF
            'footer': None,
            'max_size': 100 * 1024 * 1024,
            'min_size': 100,
        },
        'tiff_be': {
            'header': b'\x4D\x4D\x00\x2A',  # Big-endian TIFF
            'footer': None,
            'max_size': 100 * 1024 * 1024,
            'min_size': 100,
        },
        '7z': {
            'header': b'\x37\x7A\xBC\xAF\x27\x1C',
            'footer': None,
            'max_size': 100 * 1024 * 1024,
            'min_size': 100,
        },
        'rar': {
            'header': b'\x52\x61\x72\x21\x1A\x07',
            'footer': None,
            'max_size': 100 * 1024 * 1024,
            'min_size': 100,
        },
    }
    
    # RIFF-based formats need special handling (WEBP, AVI, WAV share RIFF header)
    RIFF_FORMATS = {
        b'WEBP': 'webp',
        b'AVI ': 'avi',
        b'WAVE': 'wav',
    }
    
    # ISO Base Media File Format (ftyp-based): MP4, HEIC, MOV, etc.
    FTYP_FORMATS = {
        b'isom': 'mp4', b'iso2': 'mp4', b'mp41': 'mp4', b'mp42': 'mp4',
        b'avc1': 'mp4', b'M4V ': 'mp4', b'M4A ': 'mp4',
        b'heic': 'heic', b'heix': 'heic', b'mif1': 'heic', b'msf1': 'heic',
        b'hevc': 'heic', b'hevx': 'heic',
        b'qt  ': 'mov', b'moov': 'mov',
        b'avif': 'avif',
    }
    
    def __init__(self, image_path: str, output_dir: str):
        self.image_path = Path(image_path)
        self.output_dir = Path(output_dir)
        self.logger = logging.getLogger(__name__)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.metadata_extractor = MetadataExtractor()
        self._seen_offsets: Set[int] = set()  # Dedup by start offset
        
    def carve(self, file_types: Optional[List[str]] = None) -> List[Dict]:
        """
        Perform file carving — scan raw disk for known file signatures.
        
        Args:
            file_types: List of extensions to look for (e.g. ['jpg', 'png']). 
                        If None, look for all supported.
        """
        self.logger.info(f"Starting carving on {self.image_path}")
        carved_files: List[Dict] = []
        self._seen_offsets.clear()
        
        # Filter signatures
        active_sigs: Dict[str, Dict] = {}
        if file_types:
            for ft in file_types:
                ft_clean = ft.lower().strip('.')
                if ft_clean in self.SIGNATURES:
                    active_sigs[ft_clean] = self.SIGNATURES[ft_clean]
                # Also enable RIFF/ftyp scanning if relevant types requested
        else:
            active_sigs = dict(self.SIGNATURES)
            
        if not active_sigs and not file_types:
            self.logger.warning("No valid file signatures selected for carving.")
            return []
        
        # Determine if we should scan for RIFF and ftyp formats
        scan_riff = not file_types or any(
            ft.lower().strip('.') in ('webp', 'avi', 'wav') for ft in (file_types or [])
        )
        scan_ftyp = not file_types or any(
            ft.lower().strip('.') in ('mp4', 'heic', 'heif', 'mov', 'avif') for ft in (file_types or [])
        )
            
        try:
            with open(self.image_path, 'rb') as f:
                chunk_size = 10 * 1024 * 1024  # 10MB
                # Larger overlap to catch headers near chunk boundaries
                overlap = 64 * 1024  # 64KB overlap
                offset = 0
                
                counts: Dict[str, int] = {}
                
                f.seek(0, 2)
                total_size = f.tell()
                f.seek(0)
                
                last_progress = 0
                
                while offset < total_size:
                    progress = int((offset / total_size) * 100)
                    if progress >= last_progress + 10:
                        total_found = sum(counts.values())
                        self.logger.info(f"Carving progress: {progress}% ({total_found} files found so far)")
                        last_progress = progress
                    
                    f.seek(offset)
                    read_size = min(chunk_size + overlap, total_size - offset)
                    data = f.read(read_size)
                    if not data:
                        break
                    
                    # --- Standard signature scanning ---
                    for ext, sig in active_sigs.items():
                        header = sig['header']
                        start_idx = 0
                        while True:
                            idx = data.find(header, start_idx)
                            if idx == -1:
                                break
                            
                            # Skip if in overlap zone (will be picked up next iteration)
                            if idx >= chunk_size and offset + chunk_size < total_size:
                                break
                            
                            abs_start = offset + idx
                            
                            # Skip already-processed offsets
                            if abs_start in self._seen_offsets:
                                start_idx = idx + 1
                                continue
                            
                            # Run validator if present
                            validator_name = sig.get('validator')
                            if validator_name and hasattr(self, validator_name):
                                validator = getattr(self, validator_name)
                                if not validator(data, idx):
                                    start_idx = idx + 1
                                    continue
                            
                            recovered_data = self._extract_file(
                                f, abs_start, sig.get('footer'),
                                sig['max_size'], sig.get('min_size', 0)
                            )
                            
                            if recovered_data:
                                self._seen_offsets.add(abs_start)
                                # Classify ZIP-based formats (docx, xlsx, pptx, odt)
                                actual_ext = ext
                                if ext == 'zip':
                                    actual_ext = self._classify_zip_content(recovered_data)
                                counts[actual_ext] = counts.get(actual_ext, 0) + 1
                                filename = f"carved_{counts[actual_ext]:04d}.{actual_ext}"
                                result = self._save_carved_file(filename, recovered_data, actual_ext, abs_start)
                                if result:
                                    carved_files.append(result)
                                
                            start_idx = idx + 1
                    
                    # --- RIFF-based format scanning (WEBP, AVI, WAV) ---
                    if scan_riff:
                        riff_idx = 0
                        while True:
                            ridx = data.find(b'RIFF', riff_idx)
                            if ridx == -1:
                                break
                            if ridx >= chunk_size and offset + chunk_size < total_size:
                                break
                            
                            abs_start = offset + ridx
                            if abs_start in self._seen_offsets:
                                riff_idx = ridx + 1
                                continue
                            
                            # RIFF files: bytes 0-3 = "RIFF", 4-7 = filesize (LE), 8-11 = format
                            if ridx + 12 <= len(data):
                                riff_format = data[ridx+8:ridx+12]
                                if riff_format in self.RIFF_FORMATS:
                                    ext = self.RIFF_FORMATS[riff_format]
                                    riff_size = struct.unpack_from('<I', data, ridx + 4)[0]
                                    # RIFF size doesn't include the 8-byte RIFF+size header
                                    file_size = min(riff_size + 8, 50 * 1024 * 1024)
                                    
                                    if file_size > 100:  # Minimum viable
                                        recovered_data = self._extract_exact(f, abs_start, file_size)
                                        if recovered_data:
                                            self._seen_offsets.add(abs_start)
                                            counts[ext] = counts.get(ext, 0) + 1
                                            filename = f"carved_{counts[ext]:04d}.{ext}"
                                            result = self._save_carved_file(filename, recovered_data, ext, abs_start)
                                            if result:
                                                carved_files.append(result)
                            
                            riff_idx = ridx + 1
                    
                    # --- ftyp-based format scanning (MP4, HEIC, MOV, AVIF) ---
                    if scan_ftyp:
                        ftyp_marker = b'ftyp'
                        ftyp_idx = 0
                        while True:
                            fidx = data.find(ftyp_marker, ftyp_idx)
                            if fidx == -1:
                                break
                            if fidx >= chunk_size and offset + chunk_size < total_size:
                                break
                            
                            # ftyp box: the "ftyp" string starts at offset 4 in the box
                            # Box header: 4 bytes size + 4 bytes type ("ftyp")
                            # So the box starts at fidx - 4
                            box_start = fidx - 4
                            if box_start < 0:
                                ftyp_idx = fidx + 1
                                continue
                            
                            abs_start = offset + box_start
                            if abs_start in self._seen_offsets:
                                ftyp_idx = fidx + 1
                                continue
                            
                            # Read the major brand (4 bytes after "ftyp")
                            if fidx + 8 <= len(data):
                                major_brand = data[fidx+4:fidx+8]
                                if major_brand in self.FTYP_FORMATS:
                                    ext = self.FTYP_FORMATS[major_brand]
                                    max_size = 50 * 1024 * 1024 if ext in ('heic', 'avif') else 500 * 1024 * 1024
                                    
                                    # Try to determine file size from box structure
                                    file_size = self._estimate_ftyp_size(f, abs_start, max_size)
                                    
                                    if file_size and file_size > 100:
                                        recovered_data = self._extract_exact(f, abs_start, file_size)
                                        if recovered_data:
                                            self._seen_offsets.add(abs_start)
                                            counts[ext] = counts.get(ext, 0) + 1
                                            filename = f"carved_{counts[ext]:04d}.{ext}"
                                            result = self._save_carved_file(filename, recovered_data, ext, abs_start)
                                            if result:
                                                carved_files.append(result)
                            
                            ftyp_idx = fidx + 1
                    
                    offset += chunk_size
                    
        except Exception as e:
            self.logger.error(f"Carving failed: {e}", exc_info=True)
            
        total_found = sum(counts.values())
        self.logger.info(f"Carving complete. Found {total_found} files: "
                        + ", ".join(f"{k}={v}" for k, v in sorted(counts.items()) if v > 0))
        return carved_files

    def _save_carved_file(self, filename: str, data: bytes, ext: str, 
                          abs_start: int) -> Optional[Dict]:
        """Save carved data to file and return info dict."""
        try:
            out_file = self.output_dir / filename
            with open(out_file, 'wb') as out:
                out.write(data)
            
            file_hash = hashlib.sha256(data[:65536]).hexdigest()
            
            return {
                'name': filename,
                'size': len(data),
                'type': ext,
                'path': str(out_file),
                'offset': abs_start,
                'hash': file_hash,
                'source': 'carved',
                'status': 'unknown',
                'is_duplicate': False,
                'metadata': None,
            }
        except Exception as e:
            self.logger.error(f"Failed to save carved file {filename}: {e}")
            return None

    def _extract_file(self, f, start_offset: int, footer: Optional[bytes], 
                      max_size: int, min_size: int = 0) -> Optional[bytes]:
        """Extract file data from disk using header/footer boundaries."""
        try:
            f.seek(start_offset)
            
            if footer:
                # Read up to max_size to find footer
                chunk = f.read(max_size)
                
                footer_idx = chunk.find(footer)
                if footer_idx != -1:
                    end_idx = footer_idx + len(footer)
                    if end_idx >= min_size:
                        return chunk[:end_idx]
                    return None
                else:
                    # AGGRESSIVE RECOVERY: Footer not found within max_size.
                    # On COW filesystems, data may not be contiguous.
                    # Still save what we have — it may be partially recoverable.
                    # Use a heuristic: save if the data looks valid enough.
                    if len(chunk) >= min_size and self._looks_valid(chunk, footer):
                        self.logger.debug(
                            f"Footer not found at offset {start_offset}, "
                            f"saving {len(chunk)} bytes (aggressive recovery)")
                        return chunk
                    return None
            else:
                # No footer — read a reasonable amount
                data = f.read(min(max_size, 2 * 1024 * 1024))  # 2MB default for footer-less
                if len(data) >= min_size:
                    return data
                return None
                
        except Exception:
            return None

    def _extract_exact(self, f, start_offset: int, size: int) -> Optional[bytes]:
        """Extract exact number of bytes from disk."""
        try:
            f.seek(start_offset)
            data = f.read(size)
            return data if data else None
        except Exception:
            return None

    def _looks_valid(self, data: bytes, expected_footer: Optional[bytes]) -> bool:
        """
        Heuristic check: does this data look like a real file rather than garbage?
        Used for aggressive recovery when footer is not found.
        """
        if len(data) < 1024:
            return False
        
        # Check if the file has reasonable entropy (not all zeros or all ones)
        sample = data[:4096]
        unique_bytes = len(set(sample))
        
        # All zeros or very low entropy = likely free space
        if unique_bytes < 10:
            return False
        
        # For JPEG specifically: check for JFIF/Exif markers near the start
        if data[:3] == b'\xFF\xD8\xFF':
            # Look for APP0 (JFIF) or APP1 (Exif) markers
            if b'JFIF' in data[:20] or b'Exif' in data[:20]:
                return True
            # Also check for APP markers (FF E0-EF)
            if len(data) > 3 and 0xE0 <= data[3] <= 0xEF:
                return True
        
        # For PNG: already has very specific header, if we got here it's likely valid
        if data[:8] == b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A':
            return True
        
        return False

    def _classify_zip_content(self, data: bytes) -> str:
        """
        Classify ZIP-based content by inspecting internal file paths.
        
        DOCX, XLSX, PPTX, and ODT files are all ZIP archives with
        specific internal directory structures. This method peeks
        inside the carved ZIP data to determine the actual format.
        
        Returns:
            Actual file extension: 'docx', 'xlsx', 'pptx', 'odt', or 'zip'
        """
        import zipfile
        import io
        
        try:
            with zipfile.ZipFile(io.BytesIO(data), 'r') as zf:
                names = set(zf.namelist())
                
                # DOCX: contains word/document.xml
                if any(n.startswith('word/') for n in names):
                    return 'docx'
                
                # XLSX: contains xl/workbook.xml or xl/worksheets/
                if any(n.startswith('xl/') for n in names):
                    return 'xlsx'
                
                # PPTX: contains ppt/presentation.xml or ppt/slides/
                if any(n.startswith('ppt/') for n in names):
                    return 'pptx'
                
                # ODT/ODS/ODP: contains content.xml + META-INF/manifest.xml
                if 'content.xml' in names and any(n.startswith('META-INF/') for n in names):
                    return 'odt'
                
        except (zipfile.BadZipFile, Exception):
            # Not a valid ZIP or corrupted — keep as generic zip
            pass
        
        return 'zip'

    def _validate_bmp(self, data: bytes, idx: int) -> bool:
        """Validate a BMP header to avoid false positives from 'BM' occurring in random data."""
        if idx + 14 > len(data):
            return False
        try:
            file_size = struct.unpack_from('<I', data, idx + 2)[0]
            # BMP file size should be reasonable
            return 100 < file_size < 100 * 1024 * 1024
        except Exception:
            return False

    def _estimate_ftyp_size(self, f, start_offset: int, max_size: int) -> Optional[int]:
        """
        Estimate file size of an ISO Base Media File Format file (MP4/HEIC/MOV)
        by walking the top-level box structure.
        """
        try:
            f.seek(start_offset)
            total = 0
            
            while total < max_size:
                header = f.read(8)
                if len(header) < 8:
                    break
                
                box_size = struct.unpack('>I', header[:4])[0]
                
                if box_size == 0:
                    # Box extends to end of file — use max_size
                    return min(max_size, 50 * 1024 * 1024)
                elif box_size == 1:
                    # 64-bit extended size
                    ext = f.read(8)
                    if len(ext) < 8:
                        break
                    box_size = struct.unpack('>Q', ext)[0]
                
                if box_size < 8 or box_size > max_size:
                    break
                
                total += box_size
                f.seek(start_offset + total)
                
                # Known terminal boxes
                box_type = header[4:8]
                if box_type == b'mdat':
                    return total  # mdat is usually the last meaningful box
            
            return total if total > 100 else None
            
        except Exception:
            return None

    def extract_metadata(self, file_info: Dict) -> Dict:
        """
        Extract embedded metadata from a carved file.
        
        Call this on-demand for files the user wants to inspect.
        
        Args:
            file_info: A carved file dict with 'path' key
            
        Returns:
            Updated file_info with 'metadata' populated
        """
        if file_info.get('metadata') is None:
            path = file_info.get('path', '')
            if path:
                file_info['metadata'] = self.metadata_extractor.extract(path)
        return file_info
