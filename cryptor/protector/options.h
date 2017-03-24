#pragma once
struct Options
{
	//Принудительная упаковка - будет упакован даже
	//потенциально некорректный файл
	bool force_mode;
	//Обрезать ли DOS-заголовок
	bool strip_dos_headers;
	bool rc5;
	bool anti_debug;
	//Шифрование данных
	bool crypt;
	//Перепаковывать ли директорию конфигурации загрузки
	bool rebuild_load_config;
	//Перепаковывать ли ресурсы
	bool repack_resources = true;
	//Файловое выравнивание после упаковки
	unsigned long file_alignment = 512;//512

};
