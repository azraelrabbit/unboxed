using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Unboxed
{
    internal class Program
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct BOXED_ENTRY_HEADER
        {
            public UInt32 Size;
            public UInt32 Type;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct BOXED_FILE_HEADER
        {
            public BOXED_ENTRY_HEADER Header;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 46)]
            public byte[] UnknownBytes;
            public UInt32 FileNamePos;
            public UInt32 Unknown1Pos;
            public UInt32 Unknown2Pos;
            public UInt32 FilePathPos;
            public UInt32 DataPos;
        }

        private static void HandleHeader(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                var length = stream.Length;
                var headerSize = Marshal.SizeOf(typeof (BOXED_ENTRY_HEADER));
                using (var reader = new BinaryReader(stream))
                {
                    long current = 0;
                    while (current + headerSize < length)
                    {
                        var entryHeader = PeManager.FromBinaryReader<BOXED_ENTRY_HEADER>(reader);
                        if (entryHeader.Size == 0) break;
                        reader.BaseStream.Seek(-headerSize, SeekOrigin.Current);
                        var rawData = reader.ReadBytes((int) entryHeader.Size);
                        current += entryHeader.Size;
                        if (entryHeader.Type == 65541) HandleFileEntry(rawData);
                    }
                }
            }
        }

        private static void HandleFileEntry(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                var length = stream.Length;
                if (length < 8) return;
                using (var reader = new BinaryReader(stream))
                {
                    var fileHeader = PeManager.FromBinaryReader<BOXED_FILE_HEADER>(reader);
                    reader.BaseStream.Seek(fileHeader.FileNamePos, SeekOrigin.Begin);
                    //var fileName = Encoding.Unicode.GetString(reader.ReadBytes((int) (fileHeader.Unknown1Pos - fileHeader.FileNamePos - 2)));
                    reader.BaseStream.Seek(fileHeader.FilePathPos, SeekOrigin.Begin);
                    var filePath = Encoding.Unicode.GetString(reader.ReadBytes((int) (fileHeader.DataPos - fileHeader.FilePathPos - 2))).Replace("<ExeDir>\\", "");
                    reader.BaseStream.Seek(fileHeader.DataPos, SeekOrigin.Begin);
                    if (length - fileHeader.DataPos <= 0) return;
                    var fileData = reader.ReadBytes((int) (length - fileHeader.DataPos));
                    var path = Path.GetDirectoryName(filePath);
                    if (!string.IsNullOrWhiteSpace(path) && !Directory.Exists(path)) Directory.CreateDirectory(path);
                    File.WriteAllBytes(filePath, fileData);
                    Console.WriteLine("Exported file: " + filePath);
                }
            }
        }

        private static void Main(string[] args)
        {
            if (args.Length == 0 || !File.Exists(args[0]))
            {
                Console.WriteLine("Please pass a file.");
                return;
            }

            var fileName = Path.GetFileNameWithoutExtension(args[0]);
            var extension = Path.GetExtension(args[0]);
            if (!fileName.EndsWith("_original") && !File.Exists(fileName + "_original" + extension))
            {
                File.Copy(fileName + extension, fileName + "_original" + extension);
            }

            var peHeader = new PeManager(fileName + "_original" + extension);
            for (var i = 0; i < peHeader.ImageSectionHeaders.Length; i++)
            {
                var sectionHeader = peHeader.ImageSectionHeaders[i];
                if (!sectionHeader.Name.StartsWith(".bxpck")) continue;
                Console.WriteLine("Found .bxpck section");
                HandleHeader(peHeader.ImageSectionData[i]);
                peHeader.RemoveSection(sectionHeader);
                break;
            }
            if (File.Exists(fileName + extension)) File.Delete(fileName + extension);
            peHeader.Save(fileName + extension);
            Console.WriteLine("Finished...");
            Console.ReadLine();
        }
    }
}
