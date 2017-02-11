using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;

namespace Cypher
{
    class Program
    {
        static Dictionary<uint, int> searchFreeSpace(string pathExe, uint codeStart, uint codeEnd)
        {
            byte[] program = File.ReadAllBytes(pathExe);
            uint offset = 0x0;
            int lastByte = 0;
            int m = 0;
            int freeSpaceCount = 0;
            uint savedOffset = 0;
            Dictionary<uint, int> finded = new Dictionary<uint, int>();

            uint a = codeStart + codeEnd;

            for(uint i = codeStart; i < (codeStart + codeEnd); i++)
            {
                offset = (i / 0x10) << 4;
                m = program[i];

                if(m == 0)
                {
                    if (lastByte == 0)
                    {
                        if (savedOffset == 0)
                        {
                            savedOffset = offset | i;
                        }
                        freeSpaceCount++;

                        if(i == a - 1)
                        {
                            finded[savedOffset] = freeSpaceCount;
                        }
                    }

                    lastByte = m;
                }
                else
                {
                    if (freeSpaceCount >= 30)
                    {
                        finded[savedOffset] = freeSpaceCount;
                    }

                    savedOffset = 0;
                    freeSpaceCount = 0;
                }
            }

            return finded;
        }

        static void hexView(string pathExe)
        {
            byte[] program = File.ReadAllBytes(pathExe);
            int jump = 0;
            int offset = 0x0;

            for (int i = 0; i < program.Length; i++)
            {
                offset = (i / 0x10) << 4;

                if(i % 0x10 == 0)
                {
                    Console.Write(offset.ToString("X") + ": ");
                }

                Console.Write(" " + program[i].ToString("X") + " ");
                if(jump >= 15)
                {
                    Console.Write("\n");
                    jump = 0;
                }
                else
                {
                    jump++;
                }
            }
        }

        public static int getByte(uint d, byte pos)
        {
            return (int)(d >> (8 * pos)) & 0xff;
        }

        static int GetLittleEndianIntegerFromByteArray(byte[] data, int startIndex)
        {
            return (data[startIndex + 3] << 24)
                 | (data[startIndex + 2] << 16)
                 | (data[startIndex + 1] << 8)
                 | data[startIndex];
        }

        public static byte[] injectDecryptFunction(byte[] program, uint injectAt, uint codeStart, uint virtualAddress, uint entryPoint, uint imageBase)
        {
            virtualAddress = imageBase | virtualAddress;
            byte[] virtualAdressBytes = BitConverter.GetBytes(virtualAddress);
            uint endCodeEncrypted = ((injectAt - 1) - codeStart) + 0x1000 + imageBase;
            byte[] endCodeEncryptedBytes = BitConverter.GetBytes(endCodeEncrypted);
            byte[] entryPointBytes = BitConverter.GetBytes(imageBase | entryPoint);
            uint encryptLabel = ((injectAt + 15) - codeStart) + 0x1000 + imageBase;
            byte[] encryptLabelBytes = BitConverter.GetBytes(encryptLabel);

            Console.WriteLine(virtualAddress.ToString("X"));

            // mov eax, Start Encrypt Code
            program[injectAt] = 0xB8;
            program[injectAt + 1] = virtualAdressBytes[0];
            program[injectAt + 2] = virtualAdressBytes[1];
            program[injectAt + 3] = virtualAdressBytes[2];
            program[injectAt + 4] = virtualAdressBytes[3];

            // mov ebx, End Encrypt Code
            program[injectAt + 5] = 0xBB;
            program[injectAt + 6] = endCodeEncryptedBytes[0];
            program[injectAt + 7] = endCodeEncryptedBytes[1];
            program[injectAt + 8] = endCodeEncryptedBytes[2];
            program[injectAt + 9] = endCodeEncryptedBytes[3];

            // mov ecx, EntryPoint
            program[injectAt + 10] = 0xB9;
            program[injectAt + 11] = entryPointBytes[0];
            program[injectAt + 12] = entryPointBytes[1];
            program[injectAt + 13] = entryPointBytes[2];
            program[injectAt + 14] = entryPointBytes[3];

            // xor [eax], 0xFF
            program[injectAt + 15] = 0x80;
            program[injectAt + 16] = 0x30;
            program[injectAt + 17] = 0xFF; // Key to encrypt

            // inc eax
            program[injectAt + 18] = 0x40;

            // cmp eax, ebx
            program[injectAt + 19] = 0x3B;
            program[injectAt + 20] = 0xC3;

            // jne encrypt
            program[injectAt + 21] = 0x75;
            program[injectAt + 22] = 0xF8;

            // jmp ecx
            program[injectAt + 23] = 0xFF;
            program[injectAt + 24] = 0xE1;

            return program;
        }

        public static byte[] encryptFile(byte[] program, uint start, uint end)
        {
            for(uint i = start; i <= end; i++)
            {
                program[i] = (byte)(program[i] ^ 0xFF);
            }

            return program;
        }

        static void Main(string[] args)
        {
            if(args.Length > 0)
            {
                string pathExe = args[0];

                if(File.Exists(pathExe))
                {
                    byte[] program = File.ReadAllBytes(pathExe);

                    if(args.Length >= 2 && args[1] == "-hex")
                    {
                        hexView(pathExe);
                    }

                    PeHeaderReader reader = new PeHeaderReader(pathExe);
                    PeHeaderReader.IMAGE_SECTION_HEADER code = new PeHeaderReader.IMAGE_SECTION_HEADER();
                    bool finded = false;

                    foreach(PeHeaderReader.IMAGE_SECTION_HEADER section in reader.ImageSectionHeaders)
                    {
                        string name = code.Section;

                        if(name == ".text" || name == ".code")
                        {
                            code = section;
                            finded = true;
                            break;
                        }
                    }

                    uint codeStart = 0;
                    uint codeEnd = 0;

                    if(finded)
                    {
                        codeStart = code.PointerToRawData;
                        codeEnd = code.SizeOfRawData;

                        Console.WriteLine("Code Start Finded: " + codeStart.ToString("X"));
                        Console.WriteLine("Code End Finded: " + codeEnd.ToString("X"));
                    }
                    else
                    {
                        Console.WriteLine("Canot find the .code section, please enter manualy:\n");

                        Console.Write("Code Section Start: ");
                        codeStart = UInt32.Parse(Console.ReadLine(), System.Globalization.NumberStyles.HexNumber);

                        Console.Write("Code Section Size: ");
                        codeEnd = UInt32.Parse(Console.ReadLine(), System.Globalization.NumberStyles.HexNumber);
                    }

                    Console.WriteLine("\nSearching Free Space to Allocated Code...");

                    Dictionary<uint, int> space = searchFreeSpace(pathExe, codeStart, codeEnd);

                    if (space.Count > 0)
                    {
                        Console.WriteLine("List of free space, select: ");

                        Console.WriteLine("#####################################");
                        Console.WriteLine("# Offset       # Size               #)");

                        foreach (KeyValuePair<uint, int> ele in space)
                        {
                            Console.WriteLine("# " + ele.Key.ToString("X") + " # " + ele.Value.ToString("X"));
                        }

                        Console.Write("#####################################\n");

                        uint offset = 0;

                        Console.Write("Enter Selected Offset: ");
                        offset = UInt32.Parse(Console.ReadLine(), System.Globalization.NumberStyles.HexNumber);

                        if(space.ContainsKey(offset))
                        {
                            uint virtualAddress = 0;
                            uint virtualSize = 0;
                            bool virtualFinded = false;

                            foreach (PeHeaderReader.IMAGE_SECTION_HEADER section in reader.ImageSectionHeaders)
                            {
                                if (section.PointerToRawData == codeStart && section.SizeOfRawData == codeEnd)
                                {
                                    virtualAddress = section.VirtualAddress;
                                    virtualSize = section.VirtualSize;
                                    virtualFinded = true;
                                }
                            }

                            if (!virtualFinded)
                            {
                                Console.WriteLine("Virtual Address can not fided, please enter manualy\n");

                                Console.Write("Virtual Address: ");
                                virtualAddress = UInt32.Parse(Console.ReadLine(), System.Globalization.NumberStyles.HexNumber);

                                Console.Write("Virtual Size: ");
                                virtualSize = UInt32.Parse(Console.ReadLine(), System.Globalization.NumberStyles.HexNumber);
                            }
                            else
                            {
                                Console.WriteLine("\nVirtual Adress Finded: " + virtualAddress.ToString("X"));
                                Console.WriteLine("Virtual Size Finded: " + virtualSize.ToString("X") + "\n");
                            }

                            uint entryPoint = 0;

                            if (reader.Is32BitHeader)
                            {
                                entryPoint = reader.OptionalHeader32.AddressOfEntryPoint;
                            }
                            else
                            {
                                entryPoint = reader.OptionalHeader64.AddressOfEntryPoint;
                            }

                            Console.WriteLine("\nInjecting Code...");
                            program = injectDecryptFunction(program, offset, codeStart, virtualAddress, entryPoint, reader.OptionalHeader32.ImageBase);
                            Console.WriteLine("Code Injected");

                            Console.WriteLine("\nEncrypting File");
                            program = encryptFile(program, codeStart, offset - 1);
                            Console.WriteLine("File succesly encrypted");

                            uint OEP = ((offset) - codeStart) + 0x1000 + reader.OptionalHeader32.ImageBase;

                            reader.optionalHeader32.AddressOfEntryPoint = OEP;

                            reader.Write<PeHeaderReader.IMAGE_OPTIONAL_HEADER32>(reader.getBinaryReader());

                            program = reader.getBinaryReader().ReadBytes(program.Length);

                            Console.WriteLine("File saved as encrypt.exe");
                            File.WriteAllBytes("encrypted3.exe", program);
                        }
                        else
                        {
                            Console.WriteLine("Selected Offset is Invalid");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Soory dont find free space to allocatted encrypt function");
                    }
                }
                else
                {
                    Console.WriteLine("Flie not exists");
                }
            }
            else
            {
                Console.WriteLine("Invliad Usage");
                Console.WriteLine("Cypher.exe <path_to_exe>");
            }
        }
    }
}
