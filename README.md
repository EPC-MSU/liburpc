# libserialport

В проекте используется библиотека libserialport. Нужно взять архив libserialport_release.

## Windows

Нужно положить папку из архива libserialport_release рядом с liburpc.

## Linux

Нужно установить пакет из папки deb64 (архитектура debian x64) или deb_mips (архитектура debian mipsel):

```shell
sudo apt-get install <путь до libserialport.deb>
```

# liburpc

liburpc это протоколонезависимая часть библиотеки uRPC

Обычно она собирается либо как часть библиотеки uRPC для работы по какому-то протоколу 
(например, как часть liburmc, liburlaser, liburio - эти библиотеки генерируются на 
urpc.ximc.ru из файла с описанием протокола, и liburpc входит в них), либо как XiNet сервер

### Клонировать проект liburpc

```shell
git clone https://github.com/EPC-MSU/liburpc
cd liburpc
git switch dev-1.0 # возможно, другая ветка или коммит
git submodule update --init --recursive
git submodule update --recursive
```

## Библиотека
### Cборка liburpc на ОС linux
 
Для сборки на ОС linux нужно сделать всего лишь cmake + make, но это принято делать в отдельной папке build, чтобы не замусоривать этот и все зависимые проекты временными файлами:
```shell
mkdir build
cd build
cmake ..
make -j$(nproc)
```

Скорее всего, вам не нужно этого делать: liburpc используется только для сборки urpc-xinet-server
и автоматически собирается вместе с ним.

### Cборка liburpc на ОС Windows

Для сборки на ОС Windows нужно использовать CMakeGUI. Запустив его, нужно указать в поле "Where is the source code" путь к корневой директории проекта liburpc. В поле "Where to build the binaries" - указать путь к папке, в которой будут находися файлы после сборки проекта. Рекомендуется выполнять сборку в отдельной папке build, чтобы не замусоривать этот и все зависимые проекты временными файлами. Нажать кнопку "Configure", выбрать "Visual Studio 12 2013 (х32)" и нажать кнопку "Finish". Нажать кнопку "Generate" и "Open Project". В открывшейся среде Visual Studio собрать проект.

## XiNet сервер 

XiNet это сервер, который запускается на Cubieboard 
(https://doc.xisupport.com/en/8smc5-usb/8SMCn-USB/Related_products/Control_via_Ethernet/Ethernet_adapters_Overview.html). 
Он нужен для работы с контроллерами по сети. Этот сервер не зависит от протокола, по сути он просто перенаправляет 
TCP трафик от xi-net://{host}/{serial} в /dev/ximc/{serial} и обратно. 
В этом же сервере есть мультиплексор. Это значит, можно запустить его на хосте, где подключено устройство, и 
подключать несколько клиентов через этот сервер. 

### Cборка/запуск xinet на ОС linux

Для сборки xinet сервера на linux нужно перейти в папку devxinet и сделать cmake + make, аналогично сборке liburpc, создав отдельную папку build:
```shell
cd devxinet
mkdir build
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

Для релизной сборки важно указать -DCMAKE_BUILD_TYPE=Release: обращения к xinet серверу
на БВВУ происходят часто, и этот код должен быть собран с высокой оптимизацией, иначе 
сервер будет зависать.

Запуск:
```shell
./urpc_xinet_server [путь_до_keyfile.sqlite][debug] 
```
Параметры необязательны.

Для запуска сервера требуются права на доступ к последовательным портам в директории `/dev`
(пользователь должен входить в группу `dialout` или быть `root`).

На Linux сервер ищет устройства в директории `/dev/ximc`,
поэтому перед началом работы нужно создать ссылки на устройства в соответствующей директории:

```shell
sudo mkdir /dev/ximc
sudo ln /dev/ttyACM0 /dev/ximc/00000001
```

### Cборка/запуск xinet на ОС Windows

Для работы xinet-сервера нужна libserialport.dll соответствующей разрядности(из libserialport_release-архива).
Для сборки xinet сервера на Windows нужно перейти в папку devxinet и собрать сервер аналогично сборке liburpc, создав отдельную папку build:

Запуск:
Двойным кликом мыши запустить исполняемый файл "urpc_xinet_server.exe". 

### Подключение клиента к устройству на ОС Windows

На Windows, чтобы подключить клиент к устройству `COMn` через XiNet сервер, нужно указать адрес `xi-net://localhost/n`
(например, для открытия устройства с `COM3`, адрес будет `xi-net://localhost/3`).
Вместо localhost может быть IP адрес компьютера, к которому подключено устройство.

### Подключение клиента к устройству на ОС Linux

На Linux, чтобы подключить клиент к устройству `/dev/ximc/<device>` через XiNet, нужно указать адрес `xi-net://localhost/<device>`
(например, для открытия устройства с `/dev/ximc/00000005`, адрес будет `xi-net://localhost/00000005`).
Вместо localhost может быть IP адрес компьютера, к которому подключено устройство.


В целом всё работает как-то так:

![readme](readme.png "Схема работы сервера")
