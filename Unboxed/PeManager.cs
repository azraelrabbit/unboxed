using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Unboxed
{
    public class PeManager
    {
        #region File Header Structures

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DOS_HEADER
        {
            public UInt16 e_magic;       // Magic number
            public UInt16 e_cblp;    // Bytes on last page of file
            public UInt16 e_cp;      // Pages in file
            public UInt16 e_crlc;    // Relocations
            public UInt16 e_cparhdr;     // Size of header in paragraphs
            public UInt16 e_minalloc;    // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;    // Maximum extra paragraphs needed
            public UInt16 e_ss;      // Initial (relative) SS value
            public UInt16 e_sp;      // Initial SP value
            public UInt16 e_csum;    // Checksum
            public UInt16 e_ip;      // Initial IP value
            public UInt16 e_cs;      // Initial (relative) CS value
            public UInt16 e_lfarlc;      // File address of relocation table
            public UInt16 e_ovno;    // Overlay number
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public UInt16[] e_res1;    // Reserved words
            public UInt16 e_oemid;       // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;     // OEM information; e_oemid specific
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public UInt16[] e_res2;    // Reserved words
            public Int32 e_lfanew;      // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_NT_HEADERS
        {
            public UInt32 Signature;
            public IMAGE_FILE_HEADER FileHeader;
            public IMAGE_OPTIONAL_HEADER32 OptionalHeader32;
            public IMAGE_OPTIONAL_HEADER64 OptionalHeader64;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_DATA_DIRECTORY
        {
            public UInt32 VirtualAddress;
            public UInt32 Size;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER32
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt32 BaseOfData;
            public UInt32 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt32 SizeOfStackReserve;
            public UInt32 SizeOfStackCommit;
            public UInt32 SizeOfHeapReserve;
            public UInt32 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_OPTIONAL_HEADER64
        {
            public UInt16 Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public UInt32 SizeOfCode;
            public UInt32 SizeOfInitializedData;
            public UInt32 SizeOfUninitializedData;
            public UInt32 AddressOfEntryPoint;
            public UInt32 BaseOfCode;
            public UInt64 ImageBase;
            public UInt32 SectionAlignment;
            public UInt32 FileAlignment;
            public UInt16 MajorOperatingSystemVersion;
            public UInt16 MinorOperatingSystemVersion;
            public UInt16 MajorImageVersion;
            public UInt16 MinorImageVersion;
            public UInt16 MajorSubsystemVersion;
            public UInt16 MinorSubsystemVersion;
            public UInt32 Win32VersionValue;
            public UInt32 SizeOfImage;
            public UInt32 SizeOfHeaders;
            public UInt32 CheckSum;
            public UInt16 Subsystem;
            public UInt16 DllCharacteristics;
            public UInt64 SizeOfStackReserve;
            public UInt64 SizeOfStackCommit;
            public UInt64 SizeOfHeapReserve;
            public UInt64 SizeOfHeapCommit;
            public UInt32 LoaderFlags;
            public UInt32 NumberOfRvaAndSizes;

            public IMAGE_DATA_DIRECTORY ExportTable;
            public IMAGE_DATA_DIRECTORY ImportTable;
            public IMAGE_DATA_DIRECTORY ResourceTable;
            public IMAGE_DATA_DIRECTORY ExceptionTable;
            public IMAGE_DATA_DIRECTORY CertificateTable;
            public IMAGE_DATA_DIRECTORY BaseRelocationTable;
            public IMAGE_DATA_DIRECTORY Debug;
            public IMAGE_DATA_DIRECTORY Architecture;
            public IMAGE_DATA_DIRECTORY GlobalPtr;
            public IMAGE_DATA_DIRECTORY TLSTable;
            public IMAGE_DATA_DIRECTORY LoadConfigTable;
            public IMAGE_DATA_DIRECTORY BoundImport;
            public IMAGE_DATA_DIRECTORY IAT;
            public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
            public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
            public IMAGE_DATA_DIRECTORY Reserved;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 8)]
            public string Name;
            public Misc Misc;
            public UInt32 VirtualAddress;
            public UInt32 SizeOfRawData;
            public UInt32 PointerToRawData;
            public UInt32 PointerToRelocations;
            public UInt32 PointerToLinenumbers;
            public UInt16 NumberOfRelocations;
            public UInt16 NumberOfLinenumbers;
            public DataSectionFlags Characteristics;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct Misc
        {
            [FieldOffset(0)]
            public UInt32 PhysicalAddress;
            [FieldOffset(0)]
            public UInt32 VirtualSize;
        }

        [Flags]
        public enum DataSectionFlags : uint
        {
            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeReg = 0x00000000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeDsect = 0x00000001,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeNoLoad = 0x00000002,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeGroup = 0x00000004,

            /// <summary>
            /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
            /// </summary>
            TypeNoPadded = 0x00000008,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeCopy = 0x00000010,

            /// <summary>
            /// The section contains executable code.
            /// </summary>
            ContentCode = 0x00000020,

            /// <summary>
            /// The section contains initialized data.
            /// </summary>
            ContentInitializedData = 0x00000040,

            /// <summary>
            /// The section contains uninitialized data.
            /// </summary>
            ContentUninitializedData = 0x00000080,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            LinkOther = 0x00000100,

            /// <summary>
            /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
            /// </summary>
            LinkInfo = 0x00000200,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            TypeOver = 0x00000400,

            /// <summary>
            /// The section will not become part of the image. This is valid only for object files.
            /// </summary>
            LinkRemove = 0x00000800,

            /// <summary>
            /// The section contains COMDAT data. For more information, see section 5.5.6, COMDAT Sections (Object Only). This is valid only for object files.
            /// </summary>
            LinkComDat = 0x00001000,

            /// <summary>
            /// Reset speculative exceptions handling bits in the TLB entries for this section.
            /// </summary>
            NoDeferSpecExceptions = 0x00004000,

            /// <summary>
            /// The section contains data referenced through the global pointer (GP).
            /// </summary>
            RelativeGP = 0x00008000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemPurgeable = 0x00020000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            Memory16Bit = 0x00020000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryLocked = 0x00040000,

            /// <summary>
            /// Reserved for future use.
            /// </summary>
            MemoryPreload = 0x00080000,

            /// <summary>
            /// Align data on a 1-byte boundary. Valid only for object files.
            /// </summary>
            Align1Bytes = 0x00100000,

            /// <summary>
            /// Align data on a 2-byte boundary. Valid only for object files.
            /// </summary>
            Align2Bytes = 0x00200000,

            /// <summary>
            /// Align data on a 4-byte boundary. Valid only for object files.
            /// </summary>
            Align4Bytes = 0x00300000,

            /// <summary>
            /// Align data on an 8-byte boundary. Valid only for object files.
            /// </summary>
            Align8Bytes = 0x00400000,

            /// <summary>
            /// Align data on a 16-byte boundary. Valid only for object files.
            /// </summary>
            Align16Bytes = 0x00500000,

            /// <summary>
            /// Align data on a 32-byte boundary. Valid only for object files.
            /// </summary>
            Align32Bytes = 0x00600000,

            /// <summary>
            /// Align data on a 64-byte boundary. Valid only for object files.
            /// </summary>
            Align64Bytes = 0x00700000,

            /// <summary>
            /// Align data on a 128-byte boundary. Valid only for object files.
            /// </summary>
            Align128Bytes = 0x00800000,

            /// <summary>
            /// Align data on a 256-byte boundary. Valid only for object files.
            /// </summary>
            Align256Bytes = 0x00900000,

            /// <summary>
            /// Align data on a 512-byte boundary. Valid only for object files.
            /// </summary>
            Align512Bytes = 0x00A00000,

            /// <summary>
            /// Align data on a 1024-byte boundary. Valid only for object files.
            /// </summary>
            Align1024Bytes = 0x00B00000,

            /// <summary>
            /// Align data on a 2048-byte boundary. Valid only for object files.
            /// </summary>
            Align2048Bytes = 0x00C00000,

            /// <summary>
            /// Align data on a 4096-byte boundary. Valid only for object files.
            /// </summary>
            Align4096Bytes = 0x00D00000,

            /// <summary>
            /// Align data on an 8192-byte boundary. Valid only for object files.
            /// </summary>
            Align8192Bytes = 0x00E00000,

            /// <summary>
            /// The section contains extended relocations.
            /// </summary>
            LinkExtendedRelocationOverflow = 0x01000000,

            /// <summary>
            /// The section can be discarded as needed.
            /// </summary>
            MemoryDiscardable = 0x02000000,

            /// <summary>
            /// The section cannot be cached.
            /// </summary>
            MemoryNotCached = 0x04000000,

            /// <summary>
            /// The section is not pageable.
            /// </summary>
            MemoryNotPaged = 0x08000000,

            /// <summary>
            /// The section can be shared in memory.
            /// </summary>
            MemoryShared = 0x10000000,

            /// <summary>
            /// The section can be executed as code.
            /// </summary>
            MemoryExecute = 0x20000000,

            /// <summary>
            /// The section can be read.
            /// </summary>
            MemoryRead = 0x40000000,

            /// <summary>
            /// The section can be written to.
            /// </summary>
            MemoryWrite = 0x80000000
        }

        #endregion File Header Structures

        #region Private Fields

        /// <summary>
        /// The DOS header
        /// </summary>
        private IMAGE_DOS_HEADER _dosHeader;

        private byte[] _dosStub;

        /// <summary>
        /// Image Section headers. Number of sections is in the file header.
        /// </summary>
        private IMAGE_SECTION_HEADER[] _imageSectionHeaders;

        private byte[][] _imageSectionData;

        private IMAGE_NT_HEADERS _ntHeaders;

        private byte[] _extraData;

        #endregion Private Fields

        #region Public Methods

        public PeManager(string filePath)
        {
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                using (var reader = new BinaryReader(stream))
                {
                    _dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                    _dosStub = reader.ReadBytes((int) (_dosHeader.e_lfanew - stream.Position));

                    _ntHeaders.Signature = reader.ReadUInt32();
                    _ntHeaders.FileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                    if (Is32BitHeader)
                        _ntHeaders.OptionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
                    else
                        _ntHeaders.OptionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);

                    _imageSectionHeaders = new IMAGE_SECTION_HEADER[_ntHeaders.FileHeader.NumberOfSections];
                    for (var headerNo = 0; headerNo < _imageSectionHeaders.Length; ++headerNo)
                        _imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);

                    // Read section data
                    _imageSectionData = new byte[_ntHeaders.FileHeader.NumberOfSections][];
                    for (var headerNo = 0; headerNo < _imageSectionHeaders.Length; ++headerNo)
                    {
                        var header = _imageSectionHeaders[headerNo];
                        // Skip to beginning of a section
                        stream.Seek(header.PointerToRawData, SeekOrigin.Begin);
                        // Read section data... and do something with it
                        _imageSectionData[headerNo] = reader.ReadBytes((int)header.SizeOfRawData);
                    }
                    var lastSection = _imageSectionHeaders[_ntHeaders.FileHeader.NumberOfSections - 1];
                    stream.Seek(lastSection.PointerToRawData + lastSection.SizeOfRawData, SeekOrigin.Begin);
                    if (stream.Position >= stream.Length) return;
                    var extraSize = reader.ReadUInt32();
                    stream.Seek(-sizeof(UInt32), SeekOrigin.Current);
                    _extraData = reader.ReadBytes((int) extraSize);
                }
            }
        }

        public void Save(string filePath)
        {
            using (var stream = new FileStream(filePath, FileMode.OpenOrCreate, FileAccess.Write))
            {
                using (var writer = new BinaryWriter(stream))
                {
                    ToBinaryWriter(writer, _dosHeader);
                    writer.Write(_dosStub);
                    writer.Write(_ntHeaders.Signature);
                    ToBinaryWriter(writer, _ntHeaders.FileHeader);
                    if (Is32BitHeader)
                        ToBinaryWriter(writer, _ntHeaders.OptionalHeader32);
                    else
                        ToBinaryWriter(writer, _ntHeaders.OptionalHeader64);
                    foreach (var imageSection in _imageSectionHeaders)
                        ToBinaryWriter(writer, imageSection);

                    for (var headerNo = 0; headerNo < _imageSectionHeaders.Length; ++headerNo)
                    {
                        stream.Seek(_imageSectionHeaders[headerNo].PointerToRawData, SeekOrigin.Begin);
                        writer.Write(_imageSectionData[headerNo]);
                    }
                    if (_extraData == null) return;
                    var lastSection = _imageSectionHeaders[_ntHeaders.FileHeader.NumberOfSections - 1];
                    stream.Seek(lastSection.PointerToRawData + lastSection.SizeOfRawData, SeekOrigin.Begin);
                    writer.Write(_extraData);
                }
            }
        }

        /// <summary>
        /// Gets the header of the .NET assembly that called this function
        /// </summary>
        /// <returns></returns>
        public static PeManager GetCallingAssemblyHeader()
        {
            return new PeManager(Assembly.GetCallingAssembly().Location);
        }

        /// <summary>
        /// Gets the header of the .NET assembly that called this function
        /// </summary>
        /// <returns></returns>
        public static PeManager GetAssemblyHeader()
        {
            return new PeManager(Assembly.GetAssembly(typeof (PeManager)).Location);
        }

        /// <summary>
        /// Reads in a block from a file and converts it to the struct
        /// type specified by the template parameter
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="reader"></param>
        /// <returns></returns>
        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            var bytes = reader.ReadBytes(Marshal.SizeOf(typeof (T)));
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            var theStructure = (T) Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof (T));
            handle.Free();
            return theStructure;
        }

        public static void ToBinaryWriter(BinaryWriter writer, object o)
        {
            var bytes = new byte[Marshal.SizeOf(o.GetType())];
            var handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            Marshal.StructureToPtr(o, handle.AddrOfPinnedObject(), true);
            writer.Write(bytes);
            handle.Free();
        }

        #endregion Public Methods

        #region Properties

        /// <summary>
        /// Gets if the file header is 32 bit or not
        /// </summary>
        public bool Is32BitHeader
        {
            get
            {
                const ushort IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }

        /// <summary>
        /// Gets the file header
        /// </summary>
        public IMAGE_FILE_HEADER FileHeader => _ntHeaders.FileHeader;

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER32 OptionalHeader32 => _ntHeaders.OptionalHeader32;

        /// <summary>
        /// Gets the optional header
        /// </summary>
        public IMAGE_OPTIONAL_HEADER64 OptionalHeader64 => _ntHeaders.OptionalHeader64;

        public IMAGE_SECTION_HEADER[] ImageSectionHeaders => _imageSectionHeaders;

        public byte[][] ImageSectionData => _imageSectionData;

        /// <summary>
        /// Gets the timestamp from the file header
        /// </summary>
        public DateTime TimeStamp
        {
            get
            {
                // Timestamp is a date offset from 1970
                var returnValue = new DateTime(1970, 1, 1, 0, 0, 0);

                // Add in the number of seconds since 1970/1/1
                returnValue = returnValue.AddSeconds(_ntHeaders.FileHeader.TimeDateStamp);
                // Adjust to local timezone
                returnValue += TimeZone.CurrentTimeZone.GetUtcOffset(returnValue);

                return returnValue;
            }
        }

        private void UpdateValues()
        {
            uint sectionAlignment;
            if (Is32BitHeader)
            {
                _ntHeaders.OptionalHeader32.SizeOfCode = 0;
                _ntHeaders.OptionalHeader32.SizeOfInitializedData = 0;
                _ntHeaders.OptionalHeader32.SizeOfUninitializedData = 0;
                sectionAlignment = _ntHeaders.OptionalHeader32.SectionAlignment;
            }
            else
            {
                _ntHeaders.OptionalHeader64.SizeOfCode = 0;
                _ntHeaders.OptionalHeader64.SizeOfInitializedData = 0;
                _ntHeaders.OptionalHeader64.SizeOfUninitializedData = 0;
                sectionAlignment = _ntHeaders.OptionalHeader64.SectionAlignment;
            }
            var lastSection = _imageSectionHeaders[_ntHeaders.FileHeader.NumberOfSections - 1];
            uint tempValue;
            if (lastSection.Misc.VirtualSize >= lastSection.SizeOfRawData)
            {
                if (lastSection.Misc.VirtualSize % sectionAlignment != 0)
                    tempValue = lastSection.Misc.VirtualSize - (lastSection.Misc.VirtualSize % sectionAlignment) + sectionAlignment;
                else
                    tempValue = lastSection.Misc.VirtualSize;
            }
            else
            {
                if (lastSection.SizeOfRawData % sectionAlignment != 0)
                    tempValue = lastSection.SizeOfRawData - (lastSection.SizeOfRawData % sectionAlignment) + sectionAlignment;
                else
                    tempValue = lastSection.SizeOfRawData;
            }
            if (Is32BitHeader)
                _ntHeaders.OptionalHeader32.SizeOfImage = tempValue + lastSection.VirtualAddress; // - _ntHeaders.OptionalHeader32.ImageBase;
            else
                _ntHeaders.OptionalHeader64.SizeOfImage = tempValue + lastSection.VirtualAddress;// - _ntHeaders.OptionalHeader32.ImageBase;
            foreach (var sectionHeader in _imageSectionHeaders)
            {
                if ((DataSectionFlags.ContentCode & sectionHeader.Characteristics) == DataSectionFlags.ContentCode)
                {
                    if (Is32BitHeader)
                        _ntHeaders.OptionalHeader32.SizeOfCode += sectionHeader.SizeOfRawData;
                    else
                        _ntHeaders.OptionalHeader64.SizeOfCode += sectionHeader.SizeOfRawData;
                }
                else if ((DataSectionFlags.ContentInitializedData & sectionHeader.Characteristics) == DataSectionFlags.ContentInitializedData)
                {
                    if (Is32BitHeader)
                        _ntHeaders.OptionalHeader32.SizeOfInitializedData += sectionHeader.SizeOfRawData;
                    else
                        _ntHeaders.OptionalHeader64.SizeOfInitializedData += sectionHeader.SizeOfRawData;
                }
                else if ((DataSectionFlags.ContentUninitializedData & sectionHeader.Characteristics) == DataSectionFlags.ContentUninitializedData)
                {
                    if (Is32BitHeader)
                        _ntHeaders.OptionalHeader32.SizeOfUninitializedData += sectionHeader.SizeOfRawData;
                    else
                        _ntHeaders.OptionalHeader64.SizeOfUninitializedData += sectionHeader.SizeOfRawData;
                }
            }
        }

        public bool RemoveSection(IMAGE_SECTION_HEADER section)
        {
            var index = Array.IndexOf(_imageSectionHeaders, section);
            for (var i = index + 1; i < _imageSectionHeaders.Length; i++)
            {
                _imageSectionHeaders[i].PointerToRawData = _imageSectionHeaders[i - 1].PointerToRawData;
                _imageSectionHeaders[i].VirtualAddress = _imageSectionHeaders[i - 1].VirtualAddress;
            }
            RemoveAt(ref _imageSectionHeaders, index);
            RemoveAt(ref _imageSectionData, index);
            _ntHeaders.FileHeader.NumberOfSections--;
            UpdateValues();
            return true;
        }

        #endregion Properties

        public static void RemoveAt<T>(ref T[] arr, int index)
        {
            for (var a = index; a < arr.Length - 1; a++)
                arr[a] = arr[a + 1];
            Array.Resize(ref arr, arr.Length - 1);
        }
    }
}