"""
Unearth Forensic Recovery Tool - Central Application Controller

This module provides the main application interface for coordinating
forensic recovery operations across XFS and Btrfs file systems.

Author: Unearth Development Team
Version: 1.0.0
"""
import logging
import json
import os
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime
from enum import Enum
import hashlib
import zipfile
import re
import xml.etree.ElementTree as ET
from core.btrfs_parser import BtrfsParser
from core.xfs_parser import XfsParser
from core.metadata_extractor import MetadataExtractor


class FileSystemType(Enum):
    """Supported file system types"""
    XFS = "xfs"
    BTRFS = "btrfs"
    UNKNOWN = "unknown"


class RecoverySession:
    """
    Manages a forensic recovery session with state tracking and audit logging.
    """
    
    def __init__(self, session_id: str, image_path: Path, output_dir: Path):
        """
        Initialize a recovery session.
        
        Args:
            session_id: Unique identifier for this session
            image_path: Path to the disk image file
            output_dir: Directory for recovered files and reports
        """
        self.session_id = session_id
        self.image_path = image_path
        self.output_dir = output_dir
        self.created_at = datetime.now()
        self.fs_type = FileSystemType.UNKNOWN
        self.recovered_files = []  # From metadata parser
        self.carved_files = []     # From file carver
        self.all_files = []        # Combined list for filtering (carved + metadata)
        self.filtered_files = []   # Currently displayed after filtering
        self.metadata = {}
        
        # Filter state for dynamic filtering
        self.filter_state = {
            'source': 'all',           # 'all', 'carved', 'metadata'
            'status': 'all',           # 'all', 'deleted', 'active', 'unknown'
            'file_type': 'all',        # 'all' or specific extension
            'show_duplicates': False,  # Whether to show duplicate carved files
        }
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary for serialization"""
        return {
            "session_id": self.session_id,
            "image_path": str(self.image_path),
            "output_dir": str(self.output_dir),
            "created_at": self.created_at.isoformat(),
            "fs_type": self.fs_type.value,
            "recovered_files_count": len(self.recovered_files),
            "carved_files_count": len(self.carved_files),
            "all_files_count": len(self.all_files),
            "filtered_files_count": len(self.filtered_files),
            "metadata": self.metadata,
            "filter_state": self.filter_state
        }


class UnearthApp:
    """
    Main application class coordinating all forensic recovery operations.
    
    This class provides a unified interface for:
    - File system detection and parsing
    - File recovery and carving
    - Metadata extraction
    - AI-powered analysis
    - Report generation
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize the Unearth application.
        
        Args:
            config_path: Optional path to configuration file
        """
        self.config = self._load_config(config_path)
        self.sessions: Dict[str, RecoverySession] = {}
        self.logger = self._setup_logging()
        
        # Module references (will be initialized when needed)
        self.xfs_parser = None
        self.btrfs_parser = None
        self.file_carver = None
        self.ai_classifier = None
        self.anomaly_detector = None
        self.keyword_searcher = None  # Renamed to avoid shadowing keyword_search() method
        self.report_generator = None
        
        self.logger.info("Unearth application initialized")
    
    def _load_config(self, config_path: Optional[Path]) -> Dict[str, Any]:
        """
        Load application configuration.
        
        Args:
            config_path: Path to JSON configuration file
            
        Returns:
            Configuration dictionary with defaults
        """
        default_config = {
            "version": "1.0.0",
            "log_level": "INFO",
            "max_file_size_mb": 500,
            "chunk_size_kb": 4096,
            "enable_ai_analysis": True,
            "enable_hash_verification": True,
            "supported_hash_algorithms": ["md5", "sha256"],
            "carving_signatures": {},
            "output_formats": ["pdf", "csv", "json"]
        }
        
        if config_path and config_path.exists():
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                default_config.update(user_config)
            except Exception as e:
                logging.warning(f"Failed to load config from {config_path}: {e}")
        
        return default_config
    
    def _setup_logging(self) -> logging.Logger:
        """
        Configure forensic-grade logging with audit trail.
        
        Returns:
            Configured logger instance
        """
        log_level = getattr(logging, self.config.get("log_level", "INFO"))
        
        # Create logs directory
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Configure root logger to capture ALL module logs
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Configure Unearth logger specifically
        logger = logging.getLogger("Unearth")
        logger.setLevel(log_level)
        
        # File handler with timestamp
        log_file = log_dir / f"Unearth_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        
        # Formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers to root logger (captures all modules including child loggers)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)
        
        # Don't add handlers to Unearth logger — it inherits from root via propagation.
        # Adding to both causes every message to be printed twice.
        
        return logger
    
    def create_session(self, image_path: str, output_dir: str) -> str:
        """
        Create a new forensic recovery session.
        
        Args:
            image_path: Path to disk image file
            output_dir: Directory for output files
            
        Returns:
            Session ID for tracking
            
        Raises:
            FileNotFoundError: If image file doesn't exist
            ValueError: If output directory cannot be created
        """
        image_path_obj = Path(image_path)
        if not image_path_obj.exists():
            raise FileNotFoundError(f"Disk image not found: {image_path}")
        
        output_dir_obj = Path(output_dir)
        output_dir_obj.mkdir(parents=True, exist_ok=True)
        
        # Generate session ID
        session_id = hashlib.md5(
            f"{image_path}{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Create session
        session = RecoverySession(session_id, image_path_obj, output_dir_obj)
        self.sessions[session_id] = session
        
        self.logger.info(f"Created session {session_id} for image: {image_path}")
        return session_id
    
    def detect_filesystem(self, session_id: str) -> FileSystemType:
        """
        Detect the file system type of the disk image.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Detected file system type
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Detecting filesystem for session {session_id}")
        
        # Try XFS parser first (simple 4-byte magic at offset 0)
        try:
            xfs_parser = XfsParser(str(session.image_path))
            with xfs_parser:
                if xfs_parser.detect_filesystem():
                    session.fs_type = FileSystemType.XFS
                    self.logger.info("Detected XFS filesystem using parser")
                    return FileSystemType.XFS
        except Exception as e:
            self.logger.debug(f"XFS detection failed: {e}")
        
        # Try Btrfs parser
        try:
            btrfs_parser = BtrfsParser(str(session.image_path))
            with btrfs_parser:
                if btrfs_parser.detect_filesystem():
                    session.fs_type = FileSystemType.BTRFS
                    self.logger.info("Detected Btrfs filesystem using parser")
                    return FileSystemType.BTRFS
        except Exception as e:
            self.logger.debug(f"Btrfs detection failed: {e}")
        
        if session.fs_type == FileSystemType.UNKNOWN:
            try:
                from core.partition_parser import PartitionTableParser
                partition_parser = PartitionTableParser(str(session.image_path))
                partitions = partition_parser.parse()
                
                if partitions:
                    self.logger.info(f"Found {len(partitions)} partitions")
                    
                    # Try to detect filesystem in each partition
                    for partition in partitions:
                        self.logger.info(f"Checking partition {partition.index}: offset={partition.offset}, size={partition.size}")
                        
                        # Try XFS with offset
                        try:
                            xfs_parser = XfsParser(str(session.image_path), offset=partition.offset)
                            with xfs_parser:
                                if xfs_parser.detect_filesystem():
                                    session.fs_type = FileSystemType.XFS
                                    session.metadata['partition_offset'] = partition.offset
                                    self.logger.info(f"Detected XFS filesystem in partition {partition.index}")
                                    return FileSystemType.XFS
                        except Exception as e:
                            self.logger.debug(f"Partition {partition.index} XFS check failed: {e}")
                        
                        # Try Btrfs with offset
                        try:
                            btrfs_parser = BtrfsParser(str(session.image_path), offset=partition.offset)
                            with btrfs_parser:
                                if btrfs_parser.detect_filesystem():
                                    session.fs_type = FileSystemType.BTRFS
                                    session.metadata['partition_offset'] = partition.offset
                                    self.logger.info(f"Detected Btrfs filesystem in partition {partition.index}")
                                    return FileSystemType.BTRFS
                        except Exception as e:
                            self.logger.debug(f"Partition {partition.index} Btrfs check failed: {e}")
                            
            except Exception as e:
                self.logger.error(f"Partition detection failed: {e}")

        # Fallback to manual detection for other filesystems (raw)
        try:
            with open(session.image_path, 'rb') as f:
                # XFS magic: 0x58465342 at offset 0
                f.seek(0)
                magic = f.read(4)
                if magic == b'XFSB':
                    session.fs_type = FileSystemType.XFS
                    self.logger.info("Detected XFS filesystem")
                    return FileSystemType.XFS
                
                # Btrfs magic: "_BHRfS_M" at offset 0x10040 (backup check)
                f.seek(0x10040)
                magic = f.read(8)
                if magic == b'_BHRfS_M':
                    session.fs_type = FileSystemType.BTRFS
                    self.logger.info("Detected Btrfs filesystem (manual)")
                    return FileSystemType.BTRFS
                
        except Exception as e:
            self.logger.error(f"Filesystem detection failed: {e}")
        
        session.fs_type = FileSystemType.UNKNOWN
        self.logger.warning("Unknown filesystem type")
        return FileSystemType.UNKNOWN
    
    def recover_deleted_files(self, session_id: str, progress_callback=None, file_filter: str = "all") -> List[Dict]:
        """
        Recover deleted files from the disk image.
        
        Args:
            session_id: Session identifier
            progress_callback: Optional callback function for progress updates (percent, message)
            file_filter: Filter for which files to recover:
                - "all": Recover all files found (default)
                - "deleted_only": Only recover deleted files
                - "active_only": Only recover active/existing files
            
        Returns:
            List of recovered file metadata
            
        Raises:
            KeyError: If session not found
            NotImplementedError: If filesystem parser not available
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Starting file recovery for session {session_id} (filter: {file_filter})")
        
        # Detect filesystem if not already done
        if session.fs_type == FileSystemType.UNKNOWN:
            self.detect_filesystem(session_id)
        
        recovered_files = []
        
        # TODO: Initialize parser based on filesystem type
        # This will be implemented when parsers are ready
        if session.fs_type == FileSystemType.XFS:
            self.logger.info("Using XFS parser")
            try:
                offset = session.metadata.get('partition_offset', 0)
                
                # Adapter for raw (current, total, msg) -> (percent, msg)
                def xfs_parser_callback(curr, total, msg):
                    if progress_callback and total > 0:
                        percent = int((curr / total) * 100)
                        progress_callback(percent, msg)
                
                self.xfs_parser = XfsParser(str(session.image_path), offset=offset, progress_callback=xfs_parser_callback)
                with self.xfs_parser:
                    recovered_files = self.xfs_parser.recover_deleted_files(session.output_dir, file_filter=file_filter)
                self.logger.info(f"XFS parser recovered {len(recovered_files)} files")
            except Exception as e:
                self.logger.error(f"XFS recovery failed: {e}")
                recovered_files = []
            
        elif session.fs_type == FileSystemType.BTRFS:
            self.logger.info("Using Btrfs parser")
            try:
                offset = session.metadata.get('partition_offset', 0)
                
                # Adapter for raw (current, total, msg) -> (percent, msg)
                def parser_callback(curr, total, msg):
                    if progress_callback and total > 0:
                        percent = int((curr / total) * 100)
                        progress_callback(percent, msg)
                
                self.btrfs_parser = BtrfsParser(str(session.image_path), offset=offset, progress_callback=parser_callback)
                with self.btrfs_parser:
                    recovered_files = self.btrfs_parser.recover_deleted_files(session.output_dir, file_filter=file_filter)
                self.logger.info(f"Btrfs parser recovered {len(recovered_files)} files")
            except Exception as e:
                self.logger.error(f"Btrfs recovery failed: {e}")
                recovered_files = []
        else:
            raise NotImplementedError(f"Parser not available for {session.fs_type.value}")
        
        session.recovered_files = recovered_files
        self.logger.info(f"Recovered {len(recovered_files)} files")
        return recovered_files
    
    def carve_files(self, session_id: str, file_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
        """
        Perform file carving based on magic numbers.
        
        Args:
            session_id: Session identifier
            file_types: Optional list of file types to carve (e.g., ['jpg', 'pdf'])
            
        Returns:
            List of carved file metadata
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Starting file carving for session {session_id}")
        
        from core.file_carver import FileCarver
        
        self.file_carver = FileCarver(str(session.image_path), session.output_dir)
        carved_files = self.file_carver.carve(file_types)
        
        session.carved_files = carved_files
        self.logger.info(f"Carved {len(carved_files)} files")
        
        # After carving, combine and deduplicate
        self.deduplicate_and_combine(session_id)
        
        return carved_files
    
    def deduplicate_and_combine(self, session_id: str) -> None:
        """
        Combine recovered and carved files, marking duplicates.
        
        Deduplication logic:
        - Compute hash of metadata-recovered files (active ones)
        - Mark carved files with matching hash as duplicates
        - Combine all files into session.all_files
        """
        session = self.sessions.get(session_id)
        if not session:
            return
        
        import hashlib
        
        # Build hash set from metadata-recovered files that are active (not deleted)
        active_hashes = set()
        for f in session.recovered_files:
            # Check if file has hash, if not compute from path
            file_hash = f.get('hash')
            if not file_hash and f.get('path') and os.path.exists(f.get('path', '')):
                try:
                    with open(f['path'], 'rb') as fp:
                        file_hash = hashlib.sha256(fp.read(65536)).hexdigest()
                        f['hash'] = file_hash
                except Exception:
                    pass
            
            # If file is active (not deleted), add to active set
            if file_hash and not f.get('deleted', False):
                active_hashes.add(file_hash)
            
            # Ensure source field
            f['source'] = 'metadata'
            f['is_duplicate'] = False
        
        # Mark carved files as duplicates if they match active files
        duplicates_found = 0
        for f in session.carved_files:
            file_hash = f.get('hash')
            if file_hash and file_hash in active_hashes:
                f['is_duplicate'] = True
                f['status'] = 'active'  # It's a copy of an active file
                duplicates_found += 1
            else:
                f['is_duplicate'] = False
                f['status'] = 'likely_deleted'  # Not matching active = likely deleted
        
        self.logger.info(f"Deduplication: {duplicates_found} carved files match active files")
        
        # Combine all files
        session.all_files = []
        session.all_files.extend(session.recovered_files)
        session.all_files.extend(session.carved_files)
        
        # Apply current filter
        self.apply_filters(session_id)
    
    def apply_filters(self, session_id: str, 
                      source: Optional[str] = None,
                      status: Optional[str] = None,
                      file_type: Optional[str] = None,
                      show_duplicates: Optional[bool] = None) -> List[Dict[str, Any]]:
        """
        Apply filters to all_files and update filtered_files.
        Does NOT re-scan - just filters existing results.
        
        Args:
            session_id: Session identifier
            source: 'all', 'carved', or 'metadata'
            status: 'all', 'deleted', 'active', 'likely_deleted', or 'unknown'
            file_type: 'all' or specific extension (e.g., 'pdf', 'jpg')
            show_duplicates: Whether to include duplicate carved files
            
        Returns:
            Filtered list of files
        """
        session = self.sessions.get(session_id)
        if not session:
            return []
        
        # Update filter state if provided
        if source is not None:
            session.filter_state['source'] = source
        if status is not None:
            session.filter_state['status'] = status
        if file_type is not None:
            session.filter_state['file_type'] = file_type
        if show_duplicates is not None:
            session.filter_state['show_duplicates'] = show_duplicates
        
        fs = session.filter_state
        filtered = []
        
        for f in session.all_files:
            # Source filter
            if fs['source'] != 'all' and f.get('source') != fs['source']:
                continue
            
            # Status filter
            file_status = f.get('status', 'unknown')
            if f.get('deleted', False):
                file_status = 'deleted'
            elif f.get('is_duplicate', False):
                file_status = 'active'
                
            if fs['status'] != 'all' and file_status != fs['status']:
                continue
            
            # File type filter
            if fs['file_type'] != 'all':
                file_ext = f.get('type', '') or os.path.splitext(f.get('name', ''))[1].lower().strip('.')
                if file_ext != fs['file_type']:
                    continue
            
            # Duplicate filter
            if not fs['show_duplicates'] and f.get('is_duplicate', False):
                continue
            
            filtered.append(f)
        
        session.filtered_files = filtered
        self.logger.debug(f"Filter applied: {len(filtered)}/{len(session.all_files)} files shown")
        return filtered
    
    def analyze_files(self, session_id: str, enable_ai: bool = True) -> Dict[str, Any]:
        """
        Perform AI-powered analysis on recovered files.
        
        Args:
            session_id: Session identifier
            enable_ai: Whether to enable AI classification and anomaly detection
            
        Returns:
            Analysis results dictionary
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Starting file analysis for session {session_id}")
        
        analysis_results = {
            "classifications": [],
            "anomalies": [],
            "keywords": []
        }
        
        # TODO: Initialize analysis modules (will be implemented later)
        # if enable_ai and self.config.get("enable_ai_analysis"):
        #     self.ai_classifier = AIClassifier()
        #     self.anomaly_detector = AnomalyDetector()
        #     analysis_results["classifications"] = self.ai_classifier.classify(files)
        #     analysis_results["anomalies"] = self.anomaly_detector.detect(files)
        
        self.logger.info(f"Analysis complete for session {session_id}")
        return analysis_results
    
    def _extract_text_lines(self, filepath: str, file_type: str) -> List[str]:
        """
        Extract searchable text lines from a file based on its format.
        
        Supports:
        - PDF files: extracts text per page using PyPDF2
        - DOCX files: unzips and parses word/document.xml
        - ODT/ODS files: unzips and parses content.xml
        - XLSX files: unzips and parses shared strings + sheet data
        - Plain text: reads as UTF-8 line by line
        
        Args:
            filepath: absolute path to the file
            file_type: file extension/type (e.g. 'pdf', 'zip', 'jpg')
            
        Returns:
            List of text lines extracted from the file.
            Returns empty list if the file can't be read or is unsupported binary.
        """
        ext = file_type.lower().strip('.')
        
        # Also check the actual file extension (carved files may have wrong type)
        actual_ext = os.path.splitext(filepath)[1].lower().strip('.')
        
        # --- PDF extraction via PyPDF2 ---
        if ext == 'pdf' or actual_ext == 'pdf':
            return self._extract_pdf_text(filepath)
        
        # --- DOCX / ODT / XLSX extraction via ZIP + XML ---
        # These are all ZIP archives containing XML files with the actual text
        if ext in ('zip', 'docx', 'odt', 'ods', 'xlsx') or \
           actual_ext in ('docx', 'odt', 'ods', 'xlsx'):
            return self._extract_office_text(filepath, actual_ext or ext)
        
        # --- Plain text fallback ---
        # Skip known binary formats that can never contain readable text
        binary_formats = {'jpg', 'jpeg', 'png', 'gif', 'bmp', 'tiff', 'webp',
                         'heic', 'mp3', 'mp4', 'avi', 'mp3_id3', '7z', 'rar'}
        if ext in binary_formats or actual_ext in binary_formats:
            return []
        
        return self._extract_plaintext(filepath)
    
    def _extract_pdf_text(self, filepath: str) -> List[str]:
        """Extract text from a PDF file using PyPDF2."""
        lines = []
        try:
            from PyPDF2 import PdfReader
            reader = PdfReader(filepath)
            for page_num, page in enumerate(reader.pages, start=1):
                page_text = page.extract_text()
                if page_text:
                    # Split into lines and add page context
                    for line in page_text.splitlines():
                        stripped = line.strip()
                        if stripped:  # skip blank lines
                            lines.append(stripped)
        except ImportError:
            self.logger.debug("PyPDF2 not installed — PDF content search disabled")
        except Exception as e:
            self.logger.debug(f"Could not extract PDF text from {filepath}: {e}")
        return lines
    
    def _extract_office_text(self, filepath: str, ext: str) -> List[str]:
        """
        Extract text from Office/ODF documents by reading their internal XML.
        
        DOCX → word/document.xml (Office Open XML)
        ODT/ODS → content.xml (OpenDocument Format)
        XLSX → xl/sharedStrings.xml + xl/worksheets/sheet*.xml
        """
        lines = []
        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                names = zf.namelist()
                
                # --- DOCX: Microsoft Word ---
                if 'word/document.xml' in names:
                    xml_data = zf.read('word/document.xml')
                    # Strip XML tags to get plain text
                    text = self._strip_xml_tags(xml_data.decode('utf-8', errors='ignore'))
                    lines.extend(line.strip() for line in text.splitlines() if line.strip())
                
                # --- ODT/ODS: LibreOffice / OpenDocument ---
                elif 'content.xml' in names:
                    xml_data = zf.read('content.xml')
                    text = self._strip_xml_tags(xml_data.decode('utf-8', errors='ignore'))
                    lines.extend(line.strip() for line in text.splitlines() if line.strip())
                
                # --- XLSX: Microsoft Excel ---
                elif 'xl/sharedStrings.xml' in names:
                    xml_data = zf.read('xl/sharedStrings.xml')
                    text = self._strip_xml_tags(xml_data.decode('utf-8', errors='ignore'))
                    lines.extend(line.strip() for line in text.splitlines() if line.strip())
                
                # --- Generic ZIP: try to find any readable text files inside ---
                else:
                    for name in names:
                        if name.endswith(('.txt', '.csv', '.xml', '.html', '.json')):
                            try:
                                data = zf.read(name).decode('utf-8', errors='ignore')
                                lines.extend(
                                    line.strip() for line in data.splitlines() if line.strip()
                                )
                            except Exception:
                                pass
                                
        except zipfile.BadZipFile:
            # Not actually a ZIP — try as plain text
            return self._extract_plaintext(filepath)
        except Exception as e:
            self.logger.debug(f"Could not extract office text from {filepath}: {e}")
        return lines
    
    def _extract_plaintext(self, filepath: str) -> List[str]:
        """Read a file as plain UTF-8 text, returning lines. Skips binary files."""
        lines = []
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    lines.append(line)
        except UnicodeDecodeError:
            # Binary file — can't read as text
            pass
        except PermissionError:
            self.logger.warning(f"Permission denied reading: {filepath}")
        except Exception as e:
            self.logger.debug(f"Could not read file {filepath}: {e}")
        return lines
    
    def _strip_xml_tags(self, xml_text: str) -> str:
        """Remove all XML/HTML tags from a string, leaving only the text content."""
        # Use regex to strip tags — faster than full XML parsing for search
        clean = re.sub(r'<[^>]+>', ' ', xml_text)
        # Collapse whitespace
        clean = re.sub(r'\s+', ' ', clean)
        return clean
    
    def keyword_search(self, session_id: str, keywords: List[str],
                       case_sensitive: bool = False,
                       search_content: bool = True,
                       max_snippet_length: int = 120) -> List[Dict[str, Any]]:
        """
        Search for keywords in recovered file names AND file contents.
        
        This is the core forensic keyword search capability. It performs:
        1. Filename matching — checks if any keyword appears in the file's name
        2. Content matching — reads each file as text and searches line-by-line,
           recording the line number and a context snippet for each hit
        
        Binary files (those that fail UTF-8 decoding) are skipped for content
        search but still checked for filename matches.
        
        Args:
            session_id: Active session identifier
            keywords: List of keyword strings to search for
            case_sensitive: If False (default), search is case-insensitive
            search_content: If True (default), search inside file contents too
            max_snippet_length: Max characters to include in content snippets
            
        Returns:
            List of match result dicts, each containing:
              - name: filename
              - path: full file path
              - size: file size in bytes
              - type: file extension/type
              - match_type: 'filename', 'content', or 'both'
              - matched_keywords: list of keywords that matched
              - content_matches: list of {line_number, line_text, keyword} dicts
              
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Keyword search: {keywords} (case_sensitive={case_sensitive}, content={search_content})")
        
        # Combine all recovered + carved files into one list to search through
        all_files = session.recovered_files + session.carved_files
        
        # Normalize keywords for case-insensitive comparison if needed
        if not case_sensitive:
            search_keywords = [kw.lower() for kw in keywords]
        else:
            search_keywords = list(keywords)
        
        results = []
        
        for file_info in all_files:
            filename = file_info.get('name', '')
            filepath = file_info.get('path', '')
            
            # --- Step 1: Check filename for keyword matches ---
            # Compare against the filename (not the full path) to avoid
            # false positives from directory names
            compare_name = filename if case_sensitive else filename.lower()
            filename_matched_keywords = [
                kw for kw in search_keywords if kw in compare_name
            ]
            
            # --- Step 2: Check file content for keyword matches ---
            # Only attempt content search if:
            #   a) search_content is enabled
            #   b) the file path exists on disk (it may have been recovered)
            content_matches = []
            content_matched_keywords = set()
            
            if search_content and filepath and os.path.isfile(filepath):
                # Extract text lines from the file based on its format.
                # Different file types need different extraction methods:
                #   - PDF: extract text per page using PyPDF2
                #   - DOCX/ODT/XLSX: unzip and parse XML content
                #   - Plain text: read as UTF-8 line by line
                text_lines = self._extract_text_lines(filepath, file_info.get('type', ''))
                
                # Search through extracted text lines for keyword matches
                for line_number, line in enumerate(text_lines, start=1):
                    compare_line = line if case_sensitive else line.lower()
                    
                    for kw in search_keywords:
                        if kw in compare_line:
                            # Found a keyword — record the match with context
                            snippet = line.strip()
                            if len(snippet) > max_snippet_length:
                                snippet = snippet[:max_snippet_length] + '...'
                            
                            content_matches.append({
                                'line_number': line_number,
                                'line_text': snippet,
                                'keyword': kw
                            })
                            content_matched_keywords.add(kw)
            
            # --- Step 3: Build result if any match was found ---
            all_matched = set(filename_matched_keywords) | content_matched_keywords
            
            if all_matched:
                # Determine the match type so the UI can show appropriate icons
                has_filename = len(filename_matched_keywords) > 0
                has_content = len(content_matched_keywords) > 0
                
                if has_filename and has_content:
                    match_type = 'both'
                elif has_filename:
                    match_type = 'filename'
                else:
                    match_type = 'content'
                
                results.append({
                    'name': filename,
                    'path': filepath,
                    'size': file_info.get('size', 0),
                    'type': file_info.get('type', 'unknown'),
                    'match_type': match_type,
                    'matched_keywords': list(all_matched),
                    'content_matches': content_matches,
                })
        
        self.logger.info(f"Keyword search complete: {len(results)} files matched out of {len(all_files)} total")
        return results
    
    def generate_report(self, session_id: str, format: str = "pdf") -> Path:
        """
        Generate forensic report for the session.
        
        Args:
            session_id: Session identifier
            format: Report format ('pdf', 'csv', 'json')
            
        Returns:
            Path to generated report file
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Generating {format} report for session {session_id}")
        
        report_path = session.output_dir / f"report_{session_id}.{format}"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        all_files = session.recovered_files + session.carved_files
        
        if format == "json":
            self._generate_json_report(session, all_files, report_path)
        elif format == "csv":
            self._generate_csv_report(session, all_files, report_path)
        elif format == "pdf":
            self._generate_pdf_report(session, all_files, report_path)
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        self.logger.info(f"Report generated: {report_path}")
        return report_path
    
    def _generate_json_report(self, session, all_files, report_path: Path):
        """Generate JSON report with full session data including metadata"""
        extractor = MetadataExtractor()
        files_with_meta = []
        for f in all_files:
            entry = dict(f)
            file_path = f.get('path', '')
            if file_path and os.path.exists(file_path):
                try:
                    entry['extracted_metadata'] = extractor.extract(file_path)
                except Exception:
                    entry['extracted_metadata'] = None
            files_with_meta.append(entry)
        
        report = {
            "report_type": "Unearth Forensic Recovery Report",
            "generated_at": datetime.now().isoformat(),
            "session": {
                "id": session.session_id,
                "image_path": str(session.image_path),
                "created_at": session.created_at.isoformat(),
                "filesystem": session.fs_type.value,
            },
            "summary": {
                "total_files": len(all_files),
                "recovered_count": len(session.recovered_files),
                "carved_count": len(session.carved_files),
                "total_size": sum(f.get('size', 0) for f in all_files),
            },
            "files": files_with_meta,
        }
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
    
    def _generate_csv_report(self, session, all_files, report_path: Path):
        """Generate CSV report with file inventory and metadata"""
        import csv
        import mimetypes
        extractor = MetadataExtractor()
        
        with open(report_path, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow([
                'Name', 'Size (bytes)', 'Type', 'MIME Type', 'Status',
                'Integrity', 'Modified', 'Hash', 'Source', 'Offset',
                'Inode', 'Permissions', 'UID', 'GID', 'Embedded Metadata'
            ])
            
            for file_info in all_files:
                # Extract embedded metadata
                meta_str = ''
                file_path = file_info.get('path', '')
                if file_path and os.path.exists(file_path):
                    try:
                        embedded = extractor.extract(file_path)
                        skip = {'file_path', 'file_name', 'file_size', 'error', 'extraction_time'}
                        parts = []
                        for k, v in embedded.items():
                            if k in skip:
                                continue
                            if isinstance(v, dict):
                                for sk, sv in v.items():
                                    parts.append(f"{sk}={sv}")
                            elif v is not None:
                                parts.append(f"{k}={v}")
                        meta_str = '; '.join(parts)
                    except Exception:
                        pass
                
                mime_type, _ = mimetypes.guess_type(file_info.get('name', ''))
                offset = file_info.get('offset', '')
                if isinstance(offset, int):
                    offset = f"0x{offset:X}"
                
                writer.writerow([
                    file_info.get('name', ''),
                    file_info.get('size', 0),
                    file_info.get('type', ''),
                    mime_type or '',
                    file_info.get('status', ''),
                    file_info.get('integrity_status', ''),
                    file_info.get('modified', ''),
                    file_info.get('hash', ''),
                    file_info.get('source', ''),
                    offset,
                    file_info.get('inode', ''),
                    file_info.get('mode', ''),
                    file_info.get('uid', ''),
                    file_info.get('gid', ''),
                    meta_str,
                ])
    
    def _generate_pdf_report(self, session, all_files, report_path: Path):
        """Generate PDF report using reportlab"""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.lib.units import inch
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.graphics.shapes import Drawing, Rect, String
            from reportlab.graphics import renderPDF
        except ImportError:
            # Fallback to plain text report if reportlab not installed
            self.logger.warning("reportlab not installed — generating text report instead")
            report_path = report_path.with_suffix('.txt')
            self._generate_text_report(session, all_files, report_path)
            return
        
        doc = SimpleDocTemplate(str(report_path), pagesize=A4,
                                topMargin=0.5*inch, bottomMargin=0.5*inch)
        elements = []
        styles = getSampleStyleSheet()
        
        # Title
        title_style = ParagraphStyle('Title', parent=styles['Title'], fontSize=22,
                                      textColor=colors.HexColor('#1E40AF'))
        elements.append(Paragraph("Unearth Forensic Recovery Report", title_style))
        elements.append(Spacer(1, 12))
        
        # Session info
        info_style = ParagraphStyle('Info', parent=styles['Normal'], fontSize=10,
                                     textColor=colors.HexColor('#374151'))
        elements.append(Paragraph(f"<b>Session ID:</b> {session.session_id}", info_style))
        elements.append(Paragraph(f"<b>Image:</b> {session.image_path}", info_style))
        elements.append(Paragraph(f"<b>Filesystem:</b> {session.fs_type.value}", info_style))
        elements.append(Paragraph(f"<b>Date:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", info_style))
        elements.append(Paragraph(f"<b>Total Files:</b> {len(all_files)}", info_style))
        total_size = sum(f.get('size', 0) for f in all_files)
        elements.append(Paragraph(f"<b>Total Size:</b> {total_size:,} bytes", info_style))
        elements.append(Spacer(1, 20))
        
        # --- Visual Charts Section ---
        elements.append(Paragraph("Visual Summary", styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        # Helper to build a horizontal bar chart Drawing
        def _build_bar_chart(title, items, chart_width=450, bar_height=18):
            """items: list of (label, count, hex_color)"""
            total = sum(c for _, c, _ in items)
            if total == 0:
                return None
            row_height = bar_height + 22  # bar + label spacing
            drawing_height = len(items) * row_height + 30  # +30 for title
            d = Drawing(chart_width, drawing_height)
            
            # Chart title
            d.add(String(0, drawing_height - 14, title,
                         fontSize=11, fontName='Helvetica-Bold',
                         fillColor=colors.HexColor('#1E293B')))
            
            y = drawing_height - 36
            max_bar_w = chart_width - 160  # leave space for labels
            
            for label, count, hex_color in items:
                pct = (count / total) * 100
                bar_w = max(int((count / total) * max_bar_w), 4)
                
                # Label text
                d.add(String(0, y + 4, f"{label}", fontSize=9, fontName='Helvetica',
                             fillColor=colors.HexColor('#374151')))
                
                # Bar background
                d.add(Rect(130, y, max_bar_w, bar_height,
                           fillColor=colors.HexColor('#E5E7EB'), strokeColor=None))
                # Bar fill
                d.add(Rect(130, y, bar_w, bar_height,
                           fillColor=colors.HexColor(hex_color), strokeColor=None))
                
                # Percentage label
                d.add(String(130 + max_bar_w + 6, y + 4,
                             f"{count} ({pct:.1f}%)", fontSize=8, fontName='Helvetica',
                             fillColor=colors.HexColor('#6B7280')))
                y -= row_height
            
            return d
        
        # 1. File Status Distribution
        from collections import Counter
        carved_count = sum(1 for f in all_files if f.get('status') == 'carved')
        deleted_count = sum(1 for f in all_files if f.get('status') in ('deleted', 'likely_deleted') or f.get('deleted'))
        active_count = sum(1 for f in all_files if f.get('status') == 'active')
        other_count = len(all_files) - carved_count - deleted_count - active_count
        
        status_items = []
        if carved_count > 0: status_items.append(("Carved", carved_count, "#F59E0B"))
        if deleted_count > 0: status_items.append(("Deleted", deleted_count, "#EF4444"))
        if active_count > 0: status_items.append(("Active", active_count, "#22C55E"))
        if other_count > 0: status_items.append(("Other", other_count, "#6B7280"))
        
        chart = _build_bar_chart("File Status Distribution", status_items)
        if chart:
            elements.append(chart)
            elements.append(Spacer(1, 14))
        
        # 2. File Types Breakdown
        type_counts = Counter(f.get('type', 'unknown') for f in all_files)
        type_colors = ['#3B82F6', '#8B5CF6', '#EC4899', '#14B8A6', '#F59E0B', '#6366F1', '#9CA3AF']
        type_items = []
        for idx, (ftype, cnt) in enumerate(type_counts.most_common(7)):
            type_items.append((ftype.upper(), cnt, type_colors[idx % len(type_colors)]))
        
        chart = _build_bar_chart("File Types Breakdown", type_items)
        if chart:
            elements.append(chart)
            elements.append(Spacer(1, 14))
        
        # 3. Integrity Verification
        verified = sum(1 for f in all_files if f.get('integrity_status') == 'verified')
        corrupted = sum(1 for f in all_files if f.get('integrity_status') == 'corrupted')
        unverified = sum(1 for f in all_files if f.get('integrity_status') == 'unverified')
        no_chk = sum(1 for f in all_files if f.get('integrity_status') == 'no_checksum')
        
        integrity_items = []
        if verified > 0: integrity_items.append(("Verified", verified, "#22C55E"))
        if corrupted > 0: integrity_items.append(("Corrupted", corrupted, "#EF4444"))
        if unverified > 0: integrity_items.append(("Unverified", unverified, "#F59E0B"))
        if no_chk > 0: integrity_items.append(("No Checksum", no_chk, "#6B7280"))
        
        chart = _build_bar_chart("Integrity Verification", integrity_items)
        if chart:
            elements.append(chart)
            elements.append(Spacer(1, 14))
        
        # --- File Inventory Table ---
        elements.append(Paragraph("File Inventory", styles['Heading2']))
        elements.append(Spacer(1, 8))
        
        table_data = [['#', 'Name', 'Size', 'Type', 'Status', 'Integrity']]
        for i, f in enumerate(all_files[:200], 1):  # Cap at 200 rows for PDF
            size = f.get('size', 0)
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1048576:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size/1048576:.1f} MB"
            
            table_data.append([
                str(i),
                f.get('name', '')[:40],
                size_str,
                f.get('type', '').upper(),
                f.get('status', ''),
                f.get('integrity_status', ''),
            ])
        
        table = Table(table_data, colWidths=[30, 180, 60, 45, 65, 70])
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1E40AF')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTSIZE', (0, 0), (-1, 0), 9),
            ('FONTSIZE', (0, 1), (-1, -1), 8),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.HexColor('#F9FAFB'), colors.white]),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#D1D5DB')),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(table)
        
        if len(all_files) > 200:
            elements.append(Spacer(1, 8))
            elements.append(Paragraph(
                f"<i>Showing 200 of {len(all_files)} files. Full list available in CSV/JSON format.</i>",
                info_style
            ))
        
        # --- Detailed File Metadata Section ---
        elements.append(Spacer(1, 20))
        elements.append(Paragraph("Detailed File Metadata", styles['Heading2']))
        elements.append(Spacer(1, 6))
        elements.append(Paragraph(
            "<i>Embedded metadata extracted from each recovered file (EXIF, PDF properties, Office document info, etc.)</i>",
            info_style
        ))
        elements.append(Spacer(1, 10))
        
        import mimetypes
        extractor = MetadataExtractor()
        
        file_heading_style = ParagraphStyle('FileHeading', parent=styles['Heading3'],
                                             fontSize=11, textColor=colors.HexColor('#1E40AF'),
                                             spaceBefore=10, spaceAfter=4)
        meta_style = ParagraphStyle('MetaText', parent=styles['Normal'], fontSize=8,
                                     textColor=colors.HexColor('#374151'),
                                     leading=11)
        
        for idx, f in enumerate(all_files[:50], 1):  # Cap at 50 files for PDF
            file_name = f.get('name', 'unknown')
            file_path = f.get('path', '')
            
            elements.append(Paragraph(f"{idx}. {file_name}", file_heading_style))
            
            # Build metadata rows
            meta_rows = []
            
            # File identity
            size = f.get('size', 0)
            if size < 1024:
                size_str = f"{size} B"
            elif size < 1048576:
                size_str = f"{size/1024:.1f} KB"
            else:
                size_str = f"{size/1048576:.1f} MB"
            
            mime_type, _ = mimetypes.guess_type(file_name)
            source = f.get('source', 'recovered' if 'inode' in f else 'carved')
            
            meta_rows.append(['File Size', f"{size_str} ({size:,} bytes)"])
            meta_rows.append(['MIME Type', mime_type or 'application/octet-stream'])
            meta_rows.append(['Recovery Source', source.title()])
            meta_rows.append(['SHA-256', f.get('hash', '—')])
            
            if f.get('offset') is not None:
                meta_rows.append(['Disk Offset', f"0x{f['offset']:X}"])
            if f.get('inode'):
                meta_rows.append(['Inode', str(f['inode'])])
            if f.get('mode'):
                meta_rows.append(['Permissions', f['mode']])
            if f.get('uid') is not None:
                meta_rows.append(['UID', str(f['uid'])])
            if f.get('gid') is not None:
                meta_rows.append(['GID', str(f['gid'])])
            if f.get('modified'):
                meta_rows.append(['Modified', f['modified']])
            if f.get('accessed'):
                meta_rows.append(['Accessed', f['accessed']])
            if f.get('changed'):
                meta_rows.append(['Changed', f['changed']])
            if f.get('integrity_status'):
                meta_rows.append(['Integrity', f['integrity_status']])
            
            # Magic bytes
            if file_path and os.path.exists(file_path):
                try:
                    with open(file_path, 'rb') as fh:
                        magic = fh.read(16)
                    hex_str = ' '.join(f'{b:02X}' for b in magic)
                    meta_rows.append(['Magic Bytes', hex_str])
                except Exception:
                    pass
            
            # Embedded metadata from MetadataExtractor
            if file_path and os.path.exists(file_path):
                try:
                    embedded = extractor.extract(file_path)
                    if embedded:
                        skip = {'file_path', 'file_name', 'file_size', 'error', 'extraction_time'}
                        for key, value in embedded.items():
                            if key in skip:
                                continue
                            if isinstance(value, dict):
                                for sk, sv in value.items():
                                    nice_key = sk.replace('_', ' ').title()
                                    sv_str = str(sv)[:80]
                                    meta_rows.append([nice_key, sv_str])
                            elif value is not None:
                                nice_key = key.replace('_', ' ').title()
                                v_str = str(value)[:80]
                                meta_rows.append([nice_key, v_str])
                except Exception:
                    pass
            
            if meta_rows:
                # Render as a mini table
                meta_table = Table(meta_rows, colWidths=[120, 330])
                meta_table.setStyle(TableStyle([
                    ('FONTSIZE', (0, 0), (-1, -1), 7),
                    ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#6B7280')),
                    ('TEXTCOLOR', (1, 0), (1, -1), colors.HexColor('#111827')),
                    ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                    ('ROWBACKGROUNDS', (0, 0), (-1, -1), [colors.HexColor('#F9FAFB'), colors.white]),
                    ('GRID', (0, 0), (-1, -1), 0.3, colors.HexColor('#E5E7EB')),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 0), (-1, -1), 2),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 2),
                ]))
                elements.append(meta_table)
                elements.append(Spacer(1, 6))
        
        if len(all_files) > 50:
            elements.append(Spacer(1, 8))
            elements.append(Paragraph(
                f"<i>Detailed metadata shown for first 50 of {len(all_files)} files. Full metadata available in JSON format.</i>",
                info_style
            ))
        
        doc.build(elements)
    
    def _generate_text_report(self, session, all_files, report_path: Path):
        """Fallback plain-text report when reportlab is not available"""
        lines = []
        lines.append("=" * 60)
        lines.append("  Unearth Forensic Recovery Report")
        lines.append("=" * 60)
        lines.append(f"Session ID:  {session.session_id}")
        lines.append(f"Image:       {session.image_path}")
        lines.append(f"Filesystem:  {session.fs_type.value}")
        lines.append(f"Date:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"Total Files: {len(all_files)}")
        lines.append("")
        lines.append("-" * 60)
        lines.append(f"{'Name':<35} {'Size':>10} {'Type':<6} {'Status':<10}")
        lines.append("-" * 60)
        for f in all_files:
            name = f.get('name', '')[:34]
            size = f.get('size', 0)
            ftype = f.get('type', '')
            status = f.get('status', '')
            lines.append(f"{name:<35} {size:>10} {ftype:<6} {status:<10}")
        lines.append("-" * 60)
        
        report_path.write_text('\n'.join(lines))
    
    def get_session_info(self, session_id: str) -> Dict[str, Any]:
        """
        Get information about a session.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session information dictionary
            
        Raises:
            KeyError: If session not found
        """
        session = self.sessions.get(session_id)
        if not session:
            raise KeyError(f"Session not found: {session_id}")
        
        return session.to_dict()
    
    def list_sessions(self) -> List[Dict[str, Any]]:
        """
        List all active sessions.
        
        Returns:
            List of session information dictionaries
        """
        return [session.to_dict() for session in self.sessions.values()]
    
    def cleanup_session(self, session_id: str) -> None:
        """
        Clean up and close a session.
        
        Args:
            session_id: Session identifier
            
        Raises:
            KeyError: If session not found
        """
        if session_id not in self.sessions:
            raise KeyError(f"Session not found: {session_id}")
        
        self.logger.info(f"Cleaning up session {session_id}")
        del self.sessions[session_id]


# Example usage and testing
if __name__ == "__main__":
    # Initialize application
    app = UnearthApp()
    
    # Create a test session (assuming test image exists)
    try:
        session_id = app.create_session(
            image_path="data/test_images/test_disk.img",
            output_dir="data/recovered_output/test_session"
        )
        print(f"Created session: {session_id}")
        
        # Detect filesystem
        fs_type = app.detect_filesystem(session_id)
        print(f"Detected filesystem: {fs_type.value}")
        
        # Get session info
        info = app.get_session_info(session_id)
        print(f"Session info: {json.dumps(info, indent=2)}")
        
    except FileNotFoundError as e:
        print(f"Note: {e}")
        print("This is expected if test image doesn't exist yet.")