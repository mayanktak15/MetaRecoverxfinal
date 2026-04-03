"""
Metadata Extractor Module.

Extracts embedded metadata from recovered files for forensic analysis.
Supports: Images (EXIF), PDFs, Office documents.
"""

import os
import logging
from pathlib import Path
from typing import Dict, Optional, Any
from datetime import datetime

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

try:
    import PyPDF2
    PYPDF2_AVAILABLE = True
except ImportError:
    PYPDF2_AVAILABLE = False


class MetadataExtractor:
    """
    Extracts embedded metadata from files.
    
    Supports:
    - JPEG/TIFF: EXIF data (camera, GPS, timestamps)
    - PNG: Text chunks
    - PDF: Document info (author, title, dates)
    - Office docs: Basic info from ZIP structure
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    def extract(self, file_path: str) -> Dict[str, Any]:
        """
        Extract metadata from a file.
        
        Args:
            file_path: Path to the file
            
        Returns:
            Dictionary of extracted metadata
        """
        path = Path(file_path)
        if not path.exists():
            return {'error': 'File not found'}
            
        ext = path.suffix.lower().strip('.')
        metadata = {
            'file_path': str(path),
            'file_name': path.name,
            'file_size': path.stat().st_size,
            'extraction_time': datetime.now().isoformat(),
        }
        
        # Extract based on file type
        if ext in ('jpg', 'jpeg', 'tiff', 'tif', 'heic'):
            metadata.update(self._extract_exif(path))
        elif ext == 'png':
            metadata.update(self._extract_png_metadata(path))
        elif ext == 'pdf':
            metadata.update(self._extract_pdf_metadata(path))
        elif ext in ('zip', 'docx', 'xlsx', 'pptx', 'odt'):
            metadata.update(self._extract_office_metadata(path))
        
        return metadata
    
    def _extract_exif(self, path: Path) -> Dict[str, Any]:
        """Extract EXIF data from JPEG/TIFF images."""
        if not PIL_AVAILABLE:
            return {'exif_error': 'PIL not available'}
            
        try:
            with Image.open(path) as img:
                exif_data = img._getexif()
                if not exif_data:
                    return {'exif': None}
                    
                metadata = {'exif': {}}
                
                # Extract key EXIF tags
                important_tags = {
                    'Make': 'camera_make',
                    'Model': 'camera_model',
                    'DateTime': 'date_taken',
                    'DateTimeOriginal': 'date_original',
                    'DateTimeDigitized': 'date_digitized',
                    'Artist': 'author',
                    'Copyright': 'copyright',
                    'Software': 'software',
                    'ImageWidth': 'width',
                    'ImageLength': 'height',
                    'Orientation': 'orientation',
                    'ExposureTime': 'exposure_time',
                    'FNumber': 'f_number',
                    'ISOSpeedRatings': 'iso',
                    'FocalLength': 'focal_length',
                    'Flash': 'flash',
                }
                
                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))
                    if tag_name in important_tags:
                        # Convert value to string if needed
                        if isinstance(value, bytes):
                            try:
                                value = value.decode('utf-8', errors='replace')
                            except:
                                value = str(value)
                        metadata['exif'][important_tags[tag_name]] = str(value)
                    
                    # Extract GPS data
                    if tag_name == 'GPSInfo':
                        gps_data = self._parse_gps(value)
                        if gps_data:
                            metadata['gps'] = gps_data
                            
                return metadata
                
        except Exception as e:
            return {'exif_error': str(e)}
    
    def _parse_gps(self, gps_info: Dict) -> Optional[Dict[str, Any]]:
        """Parse GPS EXIF data into coordinates."""
        try:
            gps_data = {}
            
            for key, value in gps_info.items():
                tag = GPSTAGS.get(key, str(key))
                gps_data[tag] = value
                
            # Calculate latitude
            if 'GPSLatitude' in gps_data and 'GPSLatitudeRef' in gps_data:
                lat = gps_data['GPSLatitude']
                lat_ref = gps_data['GPSLatitudeRef']
                lat_decimal = self._convert_to_decimal(lat)
                if lat_ref == 'S':
                    lat_decimal = -lat_decimal
                gps_data['latitude'] = lat_decimal
                
            # Calculate longitude
            if 'GPSLongitude' in gps_data and 'GPSLongitudeRef' in gps_data:
                lon = gps_data['GPSLongitude']
                lon_ref = gps_data['GPSLongitudeRef']
                lon_decimal = self._convert_to_decimal(lon)
                if lon_ref == 'W':
                    lon_decimal = -lon_decimal
                gps_data['longitude'] = lon_decimal
                
            # Only return if we have coordinates
            if 'latitude' in gps_data and 'longitude' in gps_data:
                return {
                    'latitude': gps_data['latitude'],
                    'longitude': gps_data['longitude'],
                }
            return None
            
        except Exception:
            return None
    
    def _convert_to_decimal(self, coord) -> float:
        """Convert GPS coordinates to decimal format."""
        try:
            degrees = float(coord[0])
            minutes = float(coord[1])
            seconds = float(coord[2])
            return degrees + (minutes / 60.0) + (seconds / 3600.0)
        except:
            return 0.0
    
    def _extract_png_metadata(self, path: Path) -> Dict[str, Any]:
        """Extract text chunks from PNG files."""
        if not PIL_AVAILABLE:
            return {'png_error': 'PIL not available'}
            
        try:
            with Image.open(path) as img:
                metadata = {'png_info': {}}
                
                # Get PNG text chunks
                if hasattr(img, 'info'):
                    for key, value in img.info.items():
                        if isinstance(value, (str, bytes)):
                            if isinstance(value, bytes):
                                value = value.decode('utf-8', errors='replace')
                            metadata['png_info'][key] = value
                            
                return metadata
                
        except Exception as e:
            return {'png_error': str(e)}
    
    def _extract_pdf_metadata(self, path: Path) -> Dict[str, Any]:
        """Extract metadata from PDF files."""
        if not PYPDF2_AVAILABLE:
            # Try basic extraction without PyPDF2
            return self._extract_pdf_basic(path)
            
        try:
            with open(path, 'rb') as f:
                reader = PyPDF2.PdfReader(f)
                info = reader.metadata
                
                if not info:
                    return {'pdf_metadata': None}
                    
                metadata = {'pdf_metadata': {}}
                
                # Extract standard PDF metadata
                if info.title:
                    metadata['pdf_metadata']['title'] = info.title
                if info.author:
                    metadata['pdf_metadata']['author'] = info.author
                if info.subject:
                    metadata['pdf_metadata']['subject'] = info.subject
                if info.creator:
                    metadata['pdf_metadata']['creator'] = info.creator
                if info.producer:
                    metadata['pdf_metadata']['producer'] = info.producer
                if info.creation_date:
                    metadata['pdf_metadata']['creation_date'] = str(info.creation_date)
                if info.modification_date:
                    metadata['pdf_metadata']['modification_date'] = str(info.modification_date)
                    
                # Page count
                metadata['pdf_metadata']['page_count'] = len(reader.pages)
                
                return metadata
                
        except Exception as e:
            return {'pdf_error': str(e)}
    
    def _extract_pdf_basic(self, path: Path) -> Dict[str, Any]:
        """Basic PDF metadata extraction without PyPDF2."""
        try:
            with open(path, 'rb') as f:
                content = f.read(4096)  # Read first 4KB
                
            metadata = {'pdf_metadata': {}}
            
            # Look for /Author, /Title, /Creator tags
            import re
            
            # Try to find common PDF info fields
            patterns = {
                'author': rb'/Author\s*\(([^)]+)\)',
                'title': rb'/Title\s*\(([^)]+)\)',
                'creator': rb'/Creator\s*\(([^)]+)\)',
                'producer': rb'/Producer\s*\(([^)]+)\)',
            }
            
            for field, pattern in patterns.items():
                match = re.search(pattern, content)
                if match:
                    try:
                        value = match.group(1).decode('utf-8', errors='replace')
                        metadata['pdf_metadata'][field] = value
                    except:
                        pass
                        
            return metadata
            
        except Exception as e:
            return {'pdf_error': str(e)}
    
    def _extract_office_metadata(self, path: Path) -> Dict[str, Any]:
        """Extract metadata from Office documents (ZIP-based)."""
        try:
            import zipfile
            import xml.etree.ElementTree as ET
            
            if not zipfile.is_zipfile(path):
                return {'office_error': 'Not a valid ZIP/Office file'}
                
            metadata = {'office_metadata': {}}
            
            with zipfile.ZipFile(path, 'r') as zf:
                # Look for docProps/core.xml (Office 2007+ format)
                if 'docProps/core.xml' in zf.namelist():
                    with zf.open('docProps/core.xml') as f:
                        content = f.read()
                        root = ET.fromstring(content)
                        
                        # Parse core properties
                        namespaces = {
                            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
                            'dc': 'http://purl.org/dc/elements/1.1/',
                            'dcterms': 'http://purl.org/dc/terms/',
                        }
                        
                        fields = [
                            ('dc:title', 'title'),
                            ('dc:creator', 'author'),
                            ('dc:subject', 'subject'),
                            ('dc:description', 'description'),
                            ('cp:lastModifiedBy', 'last_modified_by'),
                            ('dcterms:created', 'created'),
                            ('dcterms:modified', 'modified'),
                        ]
                        
                        for xpath, field_name in fields:
                            prefix, local = xpath.split(':')
                            elem = root.find(f'{{{namespaces[prefix]}}}{local}')
                            if elem is not None and elem.text:
                                metadata['office_metadata'][field_name] = elem.text
                                
            return metadata
            
        except Exception as e:
            return {'office_error': str(e)}
    
    def extract_batch(self, file_list: list) -> list:
        """
        Extract metadata from multiple files.
        
        Args:
            file_list: List of file paths or dicts with 'path' key
            
        Returns:
            List of metadata dicts
        """
        results = []
        for item in file_list:
            if isinstance(item, dict):
                path = item.get('path', '')
            else:
                path = str(item)
                
            if path:
                metadata = self.extract(path)
                results.append(metadata)
                
        return results
