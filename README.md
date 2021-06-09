# liburpc

liburpc это протоколонезависимая часть библиотеки uRPC

Обычно она собирается либо как часть библиотеки uRPC для работы по какому-то протоколу 
(например, как часть liburmc, liburlaser, liburio - эти библиотеки генерируются на 
urpc.ximc.ru из файла с описанием протокола, и liburpc входит в них), либо как XiNet сервер

## Библиотека

Для сборки liburpc в корне проекта сделать cmake + make:
```shell
cmake CMakeLists.txt
make -j$(nproc)
```

Скорее всего, вам не нужно это делать: обычно liburpc идёт вместе с библиотекой 
под конкретное устройство (liburmc, liburlaser и т.п.) и автоматически собирается вместе с 
ней.

## XiNet сервер

XiNet это сервер, который запускается на Cubieboard 
(https://doc.xisupport.com/en/8smc5-usb/8SMCn-USB/Related_products/Control_via_Ethernet/Ethernet_adapters_Overview.html). 
Он нужен для работы с контроллерами по сети. Этот сервер не зависит от протокола, по сути он просто перенаправляет 
TCP трафик от xi-net://{host}/{serial} в /dev/ximc/{serial} и обратно. 
В этом же сервере есть мультиплексор. Это значит, можно запустить его на хосте, где подключено устройство, и 
подключать несколько клиентов через этот сервер. 

Для сборки xinet сервера надо встать в папку devxinet и сделать cmake + make:
```shell
cd devxinet
cmake CMakeLists.txt -DCMAKE_BUILD_TYPE=Release
make
```

Для релизной сборки важно указать -DCMAKE_BUILD_TYPE=Release: обращения к xinet серверу
на БВВУ происходят часто, и этот код должен быть собран с высокой оптимизацией, иначе 
сервер будет зависать.

Запуск:
```shell
./urpc-xinet-server <путь_до_keyfile.sqlite> 
```

На Windows, чтобы подключить клиент к устройству COM3 через XiNet сервер, нужно указать путь xi-net://localhost/3
На Linux, чтобы подключить клиент к устройству /dev/ximc/00000005 через XiNet, нужно указать путь 
xi-net://localhost/00000005
Вместо localhost может быть IP адрес компьютера, к которому подключено устройство

В целом всё работает как-то так:
!readme.png!
