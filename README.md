# liburpc

liburpc это протоколонезависимая часть библиотеки uRPC

Обычно она собирается как часть библиотеки uRPC для работы по какому-то протоколу 
(например, как часть liburmc, liburlaser, liburio - эти библиотеки генерируются на 
urpc.ximc.ru из файла с описанием протокола, и liburpc входит в них)

Библиотека потребует другую библиотеку (xibridge), релиз которой нужно скачать по адресу "https://github.com/EPC-MSU/xibridge/releases".
Распаковать архив  и положить из папки в соответствии со своей  ОС, допустим, в папку c:/projects/xibridge/win64 (путь до библиотеки может быть любой). 

### Клонировать проект
git clone https://github.com/EPC-MSU/liburpc
cd liburpc
git switch dev-2.0 # возможно, другая ветка или коммит
git submodule update --init --recursive
git submodule update --recursive

### Cборка liburpc на ОС linux
 
Для сборки на ОС linux нужно сделать всего лишь cmake + make, но это принято делать в отдельной папке build, чтобы не замусоривать этот и все зависимые проекты временными файлами:
```shell
mkdir build
cd build
cmake .. -DXIBRIDGE_PATH=(путь до xibridge, например, c:/projects/xibridge/win64)
make -j$(nproc)
```

Скорее всего, вам не нужно этого делать: обычно liburpc идёт вместе с библиотекой 
под конкретное устройство (liburmc, liburlaser и т.п.) и автоматически собирается вместе с 
ней.

### Cборка liburpc на ОС Windows

Для сборки на ОС Windows нужно использовать CMakeGUI. Запустив его, нужно указать в поле "Where is the source code" путь к корневой директории проекта liburpc. В поле "Where to build the binaries" - указать путь к папке, 
в которой будут находися файлы после сборки проекта. Затем добавить запись (Add entry): имя - XIBRIDGE_PATH, тип - string, значение - путь к xibridge, (допустим c:/projects/xibridge).
Рекомендуется выполнять сборку в отдельной папке build, чтобы не замусоривать этот и все зависимые проекты временными файлами. Нажать кнопку "Configure", выбрать "Visual Studio 12 2013 (х32)" и нажать кнопку "Finish". Нажать кнопку "Generate" и "Open Project". В открывшейся среде Visual Studio собрать проект.


