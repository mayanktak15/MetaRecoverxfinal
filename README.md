# 🔍 Meta RecoverX - Exposing what lies beneath the surface

![Python Version](https://img.shields.io/badge/python-3.11+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

**Meta RecoverX** is a digital forensic investigation platform designed to help investigators uncover hidden or deleted information from digital systems. It combines data recovery techniques with intelligent content analysis in a single environment. The platform can recover deleted files from modern file systems, analyse recovered data, and assist investigators in understanding what happened on a system. Meta RecoverX also includes AI-based tools that help examine media and online content for deeper investigation.

## Features

### A. Core Recovery Engine (Technical Foundation)

These features focus on recovering as much data as possible while preserving the integrity of digital evidence.

- **Recovery of Deleted Files:** Meta RecoverX uses a combination of metadata analysis and signature based file carving to recover deleted files from Btrfs and XFS file systems. This approach improves the chances of retrieving data even when the original file system structure is partially damaged or missing.

- **Multi Format Support:** The recovery engine supports more than 16 different file types, including documents, images, audio, video, and archives. A signature database is used to identify and reconstruct these files from raw disk data.

- **Metadata Extraction:** Meta RecoverX extracts important file metadata such as timestamps, inode numbers, and file permissions. It can also read embedded metadata like EXIF information from images and properties from PDF or Office documents. This information helps investigators understand the history of recovered files.

- **File Integrity Verification:** Every recovered file is assigned a SHA256 hash. This allows investigators to confirm that the evidence has not been altered and supports proper chain of custody during investigations.

- **File Type Detection (Magic Numbers):** Files are identified using their header signatures instead of relying only on file extensions. This ensures accurate classification even when file names or extensions have been changed or removed.

### B. Usability and Forensics Suite (Analysis and Workflow)

These features help investigators organise and review recovered evidence in a structured and practical way.

- **Interactive Timeline:** Meta RecoverX collects timestamps from recovered files and presents them in a chronological timeline. This makes it easier to see patterns of activity and understand the sequence of events on a system.

- **Keyword Search:** Investigators can search through recovered text files using specific keywords such as passwords, confidential terms, or other relevant phrases. This helps locate important information quickly.

- **Forensic Report Generator:** The platform can generate structured reports that include recovered file details, metadata, integrity hashes, and search results. Reports can be exported in formats such as PDF or CSV for documentation and further analysis.

### C. AI Content Analysis and Media Forensics

These features extend Meta RecoverX beyond traditional forensic recovery and allow investigators to analyse digital media and online content.

- **Misinformation Immunity Score:** Meta RecoverX assigns a trust score to analysed content using a scoring engine that considers three main factors: metadata integrity, whether the physical or contextual claims match real world conditions, and whether the source is credible or supported by other data sources.

- **Multi Modal Content Forensics:** The system can analyse different types of media including images, videos, audio, text, and URLs. It transcribes speech from videos and audio, evaluates images for visual manipulation, and analyses text or web content for misleading claims or unreliable sources.

- **AI Generated Content Detection:** Meta RecoverX attempts to identify whether media or text has been generated using AI tools. It checks file metadata signatures and analyses patterns in the content to estimate the probability that the material was artificially generated.

- **Recycled or Decontextualised Footage Detection:** The system can compare video content against historical event databases to determine whether older footage is being reused to misrepresent current events.

- **Crisis Footage Context Verification:** Meta RecoverX validates the environment and context of a video against the claims made about it. For example, it can compare location details and historical weather data to check whether the footage matches the described time and place.

- **Whistleblower Identity Protection:** A specialised analysis flow can detect sensitive individuals in a video and anonymise them before the content is processed further. This helps protect whistleblowers or confidential sources.

- **Social Media Browser Extension:** Meta RecoverX includes a browser extension that integrates directly into social media feeds. Users can run a quick analysis on a post by clicking a Fact Check button without needing to download the content first.

- **Explainable Reports and Community Feedback:** Every analysed item generates a shareable report that explains why the system assigned a particular trust score. Users can review the reasoning and provide feedback on the accuracy of the analysis.

## User Interfaces

### A. Command Line Interface (CLI)
A terminal based interface designed for technical users, with progress indicators and detailed output during the recovery process.

### B. Graphical User Interface (GUI)
A desktop interface built using PyQt6 that allows investigators to perform recovery and analysis tasks through an easy to use visual environment.

## Directory Structure

### A. Meta RecoverX

```
MetaRecoverX/
├── run.py                      # Main launcher (CLI/GUI interactive entrypoint)
│
├── src/
│   ├── core/                    # Core recovery engines
│   │   ├── btrfs_parser.py     # Btrfs filesystem parser
│   │   ├── xfs_parser.py       # XFS filesystem parser
│   │   ├── file_carver.py      # File carving engine
│   │   ├── metadata_extractor.py  # EXIF/PDF/Office metadata extraction
│   │   └── partition_parser.py # Partition detection
│   │
│   ├── ui/                      # User interfaces
│   │   ├── cli.py              # Command-line interface
│   │   ├── gui.py              # Desktop GUI (PyQt6)
│   │
│   ├── app.py                   # Main application controller
│   └── utils.py                 # Utility functions
│
├── data/
│   ├── test_images/             # Test disk images
│   └── recovered_output/        # Recovery output directory
│
├── logs/                        # Application logs
├── README.md
├── requirements.txt
├── setup.py
└── LICENSE
```

### B. Meta RecoverX AI Agent

```
unearth-agent/
├── public/                 # Static assets and built extension files
│   └── extension/          # Output directory for the bundled browser extension
├── src/                    # Main application source code
│   ├── ai/                 # Genkit AI Backend
│   │   ├── flows/          # Individual forensic analysis flows
│   │   │   ├── analyze-image-content.ts
│   │   │   ├── analyze-text-content.ts
│   │   │   ├── analyze-url-content.ts
│   │   │   ├── anonymize-whistleblower-identity.ts
│   │   │   ├── assess-misinformation-trust-score.ts
│   │   │   ├── detect-ai-generation.ts
│   │   │   ├── detect-recycled-footage.ts
│   │   │   ├── transcribe-audio.ts
│   │   │   ├── translate-summary.ts
│   │   │   └── verify-crisis-footage-context.ts
│   │   ├── dev.ts          # Genkit development server entry point
│   │   └── genkit.ts       # Genkit initialization
│   ├── app/                # Next.js App Router (Pages, Layouts, Server Actions)
│   │   ├── api/            # Backend API routes
│   │   ├── report/         # Dynamic route for viewing public fact-check reports
│   │   ├── actions.ts      # Core Server Action ('analyzeInput') connecting frontend to AI flows
│   │   ├── layout.tsx      # Root application layout
│   │   └── page.tsx        # Main homepage / entry point
│   ├── components/         # React UI Components
│   │   ├── analysis/       # UI components for displaying detailed analysis result cards
│   │   ├── ui/             # Reusable Shadcn UI component library
│   │   ├── dashboard.tsx   # Main user interface for uploading media & triggering analysis
│   │   └── file-uploader.tsx
│   ├── extension/          # Browser Extension Source Code
│   │   ├── background.js   # Background service worker (forwards requests to web app)
│   │   └── content.js      # Content script injected into social media pages (e.g. adding 'Fact Check' buttons)
│   ├── hooks/              # Custom React Hooks (e.g., use-toast.ts)
│   └── lib/                # Utility Functions
├── reports.json            # Local JSON database for caching and storing generated reports
├── webpack.config.js       # Webpack configuration for compiling the browser extension scripts
├── tailwind.config.ts      # Tailwind CSS styling configuration
├── package.json            # Project dependencies and npm scripts
└── README.md               # Project documentation
```

## Installation

### Prerequisites

- **Python**: 3.11 or higher
- **Operating System**: Linux
- **RAM**: Minimum 4GB (16GB recommended for large images)
- **Disk Space**: Atleast 500MB for recovered data
- **Permissions**: Root/Administrator access for raw disk access

### System Dependencies

#### Ubuntu / Debian based Linux distributions
```bash
sudo apt-get update
sudo apt-get install -y \
    python3.11 \
    python3-pip \
    python3-dev \
    libmagic-dev \
    build-essential \
    git
```

#### Arch Linux based Linux distributions
```bash
sudo pacman -Syu --noconfirm
sudo pacman -S --noconfirm \
    python \
    python-pip \
    python-setuptools \
    file \
    base-devel \
    git
```

#### Fedora
```bash
sudo dnf update -y
sudo dnf install -y \
    python3.11 \
    python3-pip \
    python3-devel \
    file-devel \
    gcc \
    gcc-c++ \
    make \
    git
```

### Run Meta RecoverX

```bash
# Clone repository
git clone https://github.com/mayanktak15/MetaRecoverxfinal.git
cd MetaRecoverxfinal

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Launch Meta RecoverX
python run.py
```



## File System Support

### A. Btrfs (B-Tree File System)

#### Capabilities

- Parses the Btrfs superblock and tree roots to locate important filesystem structures.
- Traverses Copy-On-Write (COW) trees to identify file system metadata and data extents.
- Validates leaf nodes using the filesystem identifier (FSID) to ensure structural consistency.
- Supports extent based recovery of file data stored across different blocks.
- Verifies data integrity using CRC32C checksums present in Btrfs structures.
- Performs file carving to recover deleted files directly from raw disk data when metadata is unavailable.

#### Known Limitations

- Compressed extents using zlib, lzo, or zstd are currently not decompressed during recovery.
- RAID based Btrfs configurations may require additional handling depending on the storage layout.
- Due to the Copy-On-Write architecture, deleted metadata may disappear quickly, which reduces the time window for metadata based recovery.

#### Recovery Mechanism

Meta RecoverX primarily relies on file carving for Btrfs recovery because of the nature of its Copy-On-Write design. When available, metadata parsing is used as a secondary method to identify file structures and improve recovery accuracy.

### B. XFS (Extended File System)

#### Capabilities

-  Parses the XFS superblock to identify core filesystem configuration and layout.
- Analyses Allocation Groups (AG) to locate file system structures distributed across the disk.
- Supports recovery of file information through inode analysis.

#### Known Limitations

- Advanced XFS recovery features are still under development and may not cover all edge cases.
- Some complex storage layouts or fragmented data structures may require deeper analysis beyond the current implementation.

#### Recovery Mechanism

For XFS, Meta RecoverX relies mainly on metadata parsing through inode analysis to locate file information. File carving can also be used as a supplementary method to recover data directly from disk blocks when metadata is incomplete or missing.

## Legal & Ethics

### Legal Disclaimer

**Important:** Meta RecoverX is developed for legitimate digital forensic investigations, security research, and educational use. The tool should only be used on systems and data where proper authorization has been granted.

Using forensic tools without permission may violate privacy laws, organisational policies, or local regulations. Users are responsible for ensuring that they follow all applicable laws and ethical guidelines when using this software.

### Authorized Uses

- Law enforcement investigations with appropriate legal authorization  
- Corporate incident response on organisation owned systems  
- Personal data recovery on devices owned by the user  
- Security research carried out with proper consent and approval  
- Educational and training purposes on controlled test systems  

### Unauthorized Uses

- Accessing computer systems or storage devices without permission  
- Violating privacy regulations or data protection laws  
- Attempting to bypass encryption or security controls without authorization  
- Modifying, destroying, or tampering with digital evidence  
- Any activity that is illegal or unethical

### Ethical Guidelines

1. **Authorization**  
   Always obtain proper permission before analysing any system, storage device, or dataset. Investigations should only be performed on systems where legal or organisational approval has been granted.

2. **Chain of Custody**  
   Follow proper evidence handling procedures. Every step of the investigation should be traceable to ensure that the evidence remains reliable and admissible if required.

3. **Privacy**  
   Respect applicable data protection and privacy laws such as GDPR, CCPA, or other regional regulations. Sensitive data should be handled responsibly and only accessed when necessary for the investigation.

4. **Documentation**  
   Maintain clear and detailed records of all actions taken during the investigation. Proper documentation helps maintain transparency and allows others to review the process if needed.

5. **Integrity**  
   The original evidence should never be modified. Analysis should always be performed on copies or forensic images to preserve the authenticity of the data.

6. **Transparency**  
   Clearly describe the methods, tools, and processes used during the investigation. Reports should explain how conclusions were reached so that findings can be independently verified.

### Liability

The developers and contributors of Meta RecoverX provide this software **"AS IS"**, without any warranty or guarantee of performance.

By using this tool, you acknowledge the following:

- The software is provided without any express or implied warranty.
- The developers are not responsible for any misuse of the tool.
- The developers are not liable for data loss, system damage, or any other consequences resulting from its use.
- Users are encouraged to have proper training or knowledge in digital forensics before using the tool in real investigations.

## Acknowledgments

We would like to acknowledge the projects, communities, and technologies that made the development of Meta RecoverX possible.

- **Btrfs Developers** – For designing the B-Tree based Copy-On-Write filesystem and providing detailed technical documentation that helped guide the recovery implementation.

- **XFS Development Team** – For their extensive documentation on filesystem structures, which helped in understanding allocation groups, inodes, and recovery mechanisms.

- **The Sleuth Kit Team** – For building foundational open source digital forensics tools that continue to inspire modern forensic software development.

- **Open Source Community** – For the libraries, frameworks, and documentation that support the development of tools like Meta RecoverX.

- **Google Genkit** – For providing the framework used to build and orchestrate the AI analysis workflows.

- **Google Gemini Models** – For enabling multi modal analysis of text, images, audio, and video content used in the misinformation detection system.

- **Zod** – For schema validation and structured outputs in the AI analysis pipelines.

- **Next.js and React Community** – For building the web application and extension interfaces used in the Meta RecoverX Agent platform.

Their contributions have played an important role in making this project possible.

## Platform Support for Meta RecoverX

### Linux (Primary Platform)

Meta RecoverX is primarily designed to run on Linux systems, where direct access to modern file systems and low level storage devices is easier to manage.

- Native support for file systems such as **Btrfs** and **XFS**, which are commonly used in Linux environments.  
- Allows **raw disk access** with the required system permissions, making it possible to analyse storage devices and disk images directly.  
- Provides **better performance for disk I/O operations**, which is important for large scale data recovery tasks.  
- Most **digital forensic tools and libraries** are available on Linux, making it a practical platform for forensic investigations.

**Setup:**
```bash
# Grant user access to disk devices (use carefully!)
sudo usermod -aG disk $USER
```

## Support the Project

Meta RecoverX is a free and open source project. If you find it useful or interesting, there are a few simple ways you can support it.

- **Star the repository** to help others discover the project.  
- **Report bugs or suggest improvements** through issues.  
- **Contribute code or documentation** if you would like to help improve the platform.  
- **Share the project** with others who are interested in digital forensics or cybersecurity.

## Final Words

Thank you for taking the time to explore **Meta RecoverX**.

This project was built with a genuine interest in digital forensics and a belief that powerful investigative tools should be accessible to researchers, investigators, and the open source community. Whether you are recovering lost data, analysing digital evidence, or studying cybersecurity, we hope Meta RecoverX proves useful in your work.

Please remember that forensic tools carry responsibility. Always use them with proper authorization and follow ethical and legal guidelines while conducting investigations.

**Happy investigating!**

*Made with ❤️ by Meta RecoverX*  
*Last Updated: March 2026*
