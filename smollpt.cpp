#include <Windows.h>
#include <iostream>
#include <iterator>
#include <sstream>
#include <cstddef>
#include <vector>


enum class byte_type { value, wildcard };


struct pattern_byte {
	pattern_byte(byte_type _type, std::byte _byte = (std::byte)0) : type(_type), byte(_byte) {}
	pattern_byte(byte_type _type, std::string _byte) : type(_type) {
		byte = (std::byte)std::stoul(_byte, nullptr, 16);
	}

	byte_type type;
	std::byte byte;
};


class scoped_region {
public:
	uintptr_t region_end()   { return reinterpret_cast<uintptr_t>(m_memory.BaseAddress) + m_memory.RegionSize -1; }
	uintptr_t region_begin() { return reinterpret_cast<uintptr_t>(m_memory.BaseAddress); }

	scoped_region(uintptr_t address, bool set_protection = true) {
		if (VirtualQuery(reinterpret_cast<const void*>(address), &m_memory, sizeof(m_memory)) != sizeof(m_memory))
			std::invalid_argument("failed to obtain information for the provided address. code: " + GetLastError());

		std::cout << "------------------------ claiming region ------------------------\n";
		std::cout << "from: " << std::hex << reinterpret_cast<uintptr_t>(m_memory.AllocationBase) << std::endl;
		std::cout << "to:   " << std::hex << reinterpret_cast<uintptr_t>(m_memory.BaseAddress) + m_memory.RegionSize - 1 << std::endl;

		// i need to do something about page guards..
		if (set_protection) {
			m_restore = ! ((
				(m_memory.Protect & PAGE_READONLY)           ||
				(m_memory.Protect & PAGE_READWRITE)          ||
				(m_memory.Protect & PAGE_WRITECOPY)          ||
				(m_memory.Protect & PAGE_EXECUTE_READ)       ||
				(m_memory.Protect & PAGE_EXECUTE_READWRITE)  ||
				(m_memory.Protect & PAGE_EXECUTE_WRITECOPY)) &&
					! (m_memory.Protect & PAGE_NOACCESS)
			);

			std::cout << "page needs reprotection: " << m_restore << std::endl;
		}

		if (m_restore)
			if (!VirtualProtect(m_memory.BaseAddress, m_memory.RegionSize, PAGE_EXECUTE_READWRITE, &m_old_protection))
				std::invalid_argument("failed to protect memory region at the provided address. code: " + GetLastError());
	}

	~scoped_region() {
		std::cout << "unclaiming region\n\n";
		// we should be fine if this fails
		if (m_restore) VirtualProtect(m_memory.BaseAddress, m_memory.RegionSize, m_old_protection, NULL);
	}
private:
	bool m_restore = false;
	DWORD m_old_protection;
	MEMORY_BASIC_INFORMATION m_memory;
};


class memory_scanner {
public:

	uintptr_t scan(const std::string& pattern) {
		std::vector<pattern_byte> parsed_pattern = parse_pattern(pattern);

		uintptr_t current = reinterpret_cast<uintptr_t>(m_info.lpBaseOfDll);
		uintptr_t end = reinterpret_cast<uintptr_t>(m_info.lpBaseOfDll) + m_info.SizeOfImage - 1;

		std::vector<pattern_byte>::const_iterator it_pattern_byte = parsed_pattern.begin();
		bool found = false;

		std::cout << "module base: "   << std::hex << current << std::endl;
		std::cout << "end of module: " << std::hex << end     << std::endl << std::endl;

		// maybe SizeOfImage actually is the last address
		// need to look that up tho (i think x64dbg displays that)
		while (current <= end && !found) {
			// should get reconstructed every iteration
			scoped_region memory_region{ current };

			for (; current <= memory_region.region_end(); current++) {
				switch (it_pattern_byte->type) {
				case byte_type::wildcard: break;
				case byte_type::value:
					if (*reinterpret_cast<std::byte*>(current) != it_pattern_byte->byte) {
						it_pattern_byte = parsed_pattern.begin();
						continue;
					}

					break; // matched
				}

				if (++it_pattern_byte == parsed_pattern.end()) {
					found = true;
					break;
				}
			}

			if (found) break;
		}

		return found ? current : 0;
	}

	memory_scanner() {
		if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &m_info, sizeof(MODULEINFO)))
			throw std::runtime_error("failed to get module information for main module. error: " + GetLastError());
	}

private:
	MODULEINFO m_info;

	std::vector<pattern_byte> parse_pattern(const std::string& pattern) {
		std::vector<pattern_byte> parsed_bytes;

		std::istringstream stream(pattern);
		for (std::string byte_str; stream >> byte_str; ) {
			if (byte_str == "??" || byte_str == "?")
				parsed_bytes.push_back(pattern_byte(byte_type::wildcard));

			else parsed_bytes.push_back(pattern_byte(byte_type::value, byte_str));
		}

		return parsed_bytes;
	}
};


int main() {
	memory_scanner scanner{};
    std::cout << scanner.scan("AA BB CC DD EE FF"); 
}