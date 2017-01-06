#pragma once
#include <Windows.h>
#pragma pack(push, 1)
//Структура, хранящая информацию об упакованной секции
struct packed_section
{
	char name[8]; //Имя секции
	DWORD virtual_size; //Виртуальный размер
	DWORD virtual_address; //Виртуальный адрес (RVA)
	DWORD size_of_raw_data; //Размер "сырых" данных
	DWORD pointer_to_raw_data; //Файловое смещение сырых данных
	DWORD characteristics; //Характеристики секции
};

//Структура, хранящая информацию об упакованном файле
struct packed_file_info
{
	BYTE number_of_sections; //Количество секций в оригинальном файле
	DWORD size_of_packed_data; //Размер упакованных данных
	DWORD size_of_unpacked_data; //Размер оригинальных данных
	
	DWORD total_virtual_size_of_sections; //Полный виртуальный размер всех секций оригинального файла
	DWORD original_import_directory_rva; //Относительный адрес оригинальной директории импорта
	DWORD original_import_directory_size; //Размер оригинальной директории импорта
	DWORD original_entry_point; //Оригинальная точка входа
	
	DWORD original_resource_directory_rva; //Относительный адрес оригинальной директории ресурсов
	DWORD original_resource_directory_size; //Размер оригинальной директории ресурсов
	
	DWORD original_relocation_directory_rva; //Относительный адрес оригинальной директории релокаций
	DWORD original_relocation_directory_size; //Размер оригинальной директории релокаций

	DWORD original_load_config_directory_rva; //Относительный адрес оригинальной директории конфигурации загрузки

	DWORD lock_opcode; //Фиктивный опкод команды ассемблера LOCK

	//Сюда загрузчик будет записывать TLS-индекс
	DWORD tls_index;
	//Относительный адрес индекса TLS в оригинальном файле
	DWORD original_tls_index_rva;
	//Оригинальный адрес массива TLS-коллбэков в оригинальном файле
	DWORD original_rva_of_tls_callbacks;
	//Относительный адрес массива TLS-коллбэков в файле
	//после нашей модификации
	DWORD new_rva_of_tls_callbacks;

	DWORD load_library_a; //Адрес процедуры LoadLibraryA из kernel32.dll
	DWORD get_proc_address; //Адрес процедуры GetProcAddress из kernel32.dll
	DWORD end_of_import_address_table; //Конец IAT
};
#pragma pack(pop)
