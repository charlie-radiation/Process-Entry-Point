#include <Windows.h>
#include <iostream>
#include <iomanip>
#include <tlhelp32.h>



using namespace std;


HANDLE OpenProcessById(DWORD processId) 
{
    //HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    HANDLE hProcess = OpenProcess(0x0400 | 0x0010, FALSE, processId);

    if (hProcess == NULL)
	{
        std::cerr << "Failed to open the process. Error code: " << GetLastError() << std::endl;
    }

    return hProcess;
}



uintptr_t GetEntryPointAddress(DWORD processId)
 {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);

    if (hSnapshot == INVALID_HANDLE_VALUE)
		{
        return 0;
   		}

    MODULEENTRY32 moduleEntry;
    moduleEntry.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hSnapshot, &moduleEntry))
		{
        CloseHandle(hSnapshot);
        return reinterpret_cast<uintptr_t>(moduleEntry.modBaseAddr);
    	}

    CloseHandle(hSnapshot);
    return 0;
 }


int main()
{
	
	system("Color 0A");
	
	cout << "|============================= cH@rL!3.xRad!+!0n ===================================|" << endl;  
    cout << "|===================================================================================|" << endl;  
    cout << "|                             Program Description                                   |" << endl;  
    cout << "|                         Reading Windows Process Memory                            |" << endl;  
    cout << "|===================================================================================|" << endl;  
    cout << "|============================= Abdullah Awais ======================================|" << endl;  
    cout << "|===================================================================================|" << endl;  
    cout << "" << endl;
	cout << "" << endl;

	
	DWORD processId;
	cout << "Enter Process ID:";
	cin >> processId;
	cout << "[+] Process ID: " << processId << endl;
    cout << "" << endl;
	cout << "" << endl;	
	
	Sleep(3000);
	std::cerr << "[+]Opening Handle" << std::endl;

	HANDLE h1 = OpenProcessById(processId);
    if (h1 != NULL) 
				{
					LPVOID address = 0;
					while (true) 
					{
					MEMORY_BASIC_INFORMATION mbi;
					SIZE_T result = VirtualQueryEx(h1, address, &mbi, sizeof(mbi));
					if (result == 0) 
						{
							DWORD error = GetLastError();
							if (error == ERROR_NO_MORE_FILES) 
															{
																break;
															}
							else     //  Section to find Program Entry Point and Read Bytes
								{
										Sleep(3000);
										std::cerr << "[+] Fiding Entry Point Of Program" << std::endl;

										uintptr_t entryPoint = GetEntryPointAddress(processId);
										if (entryPoint == 0) 
											{
												std::cerr << "Failed to get the entry point address." << std::endl;	
												CloseHandle(h1);
												return 1;
											} 
										MEMORY_BASIC_INFORMATION memInfo;
										VirtualQueryEx(h1, reinterpret_cast<LPCVOID>(entryPoint), &memInfo, sizeof(memInfo));
                                        std::cout << "[+] Entry point is located in the memory region starting at: " << memInfo.BaseAddress << std::endl;
                                                                                
                                        CloseHandle(h1);
                                        
                                        Sleep(3000);
                                        std::cerr << "[+] Reading Bytes From Entry Point: " << memInfo.BaseAddress << std::endl;
                                        
                                        HANDLE hProcess1 = OpenProcess(PROCESS_VM_READ, FALSE, processId);
										LPVOID address = (LPVOID)memInfo.BaseAddress; // Entry Point address
										SIZE_T size = 5000;
										BYTE* buffer = new BYTE[size];
										SIZE_T bytesRead;

	
	std::cerr << "[+] Getting Bytes in HEX " << std::endl;
	std::cerr << "\n" << std::endl;
	Sleep(3000);
	
	
if (ReadProcessMemory(hProcess1, address, buffer, size, &bytesRead))
	{
		for (size_t i = 0; i < std::min<size_t>(15000, bytesRead); ++i)
			{
				std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(buffer[i]) << " ";	
			}
			std::cout << std::dec << std::endl;	
	}

	std::cerr << "\n" << std::endl;
	std::cerr << "[+] Decoding raw HEX to readable form " << std::endl;
	std::cerr << "\n" << std::endl;
	Sleep(3000);

if (ReadProcessMemory(hProcess1, address, buffer, size, &bytesRead))
    {
        for (size_t i = 0; i < bytesRead; ++i)
        {
            // Output ASCII representation
            if (isprint(buffer[i]))
            {
                std::cout << static_cast<char>(buffer[i]);
            }

            else
            {
                std::cout << ".";
            }
        }
    }

	else 
		{
		std::cerr << "[-] Failed to read process memory. Error code: " << GetLastError() << std::endl;
		CloseHandle(hProcess1);
		}
										
		return 1;
		break;
		}
	}
	std::cout << "BaseAddress: " << mbi.BaseAddress << std::endl;
    std::cout << "AllocationBase: " << mbi.AllocationBase << std::endl;
    std::cout << "RegionSize: " << mbi.RegionSize << " bytes" << std::endl;
    std::cout << std::endl;	
    address = static_cast<LPVOID>(static_cast<char*>(mbi.BaseAddress) + mbi.RegionSize);
	}
	CloseHandle(h1);
	}
	else 
	{
	std::cerr << "[-] Failed to open process. Error code: " << GetLastError() << std::endl;
	}
	CloseHandle(h1);
	return 0;    
}


