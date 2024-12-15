# **Personalización y Expansión del Kernel de Linux: Guía de Configuración y Modificaciones**

## **Introducción y Objetivos del Proyecto**

**Introducción:**
Este proyecto tiene como objetivo la expansión y personalización del kernel de Linux mediante la incorporación de nuevas
funcionalidades específicas, así como la modificación de comportamientos del sistema. Se tendrá la oportunidad de
trabajar con el núcleo de Linux, configurando un entorno de desarrollo adecuado para la compilación del kernel y
desarrollando módulos personalizados que añaden nuevas funcionalidades al sistema operativo. Al realizar estas
modificaciones, se adquieren conocimientos profundos en programación de sistemas y se entienden los principios internos
de los kernels de los sistemas operativos, todo dentro de un entorno controlado y práctico.

**Objetivos del Proyecto:**

- **Objetivo General:**
  Modificar y personalizar el kernel de Linux para agregar nuevas llamadas al sistema y funcionalidades que permitan una
  mayor interacción y control sobre el sistema operativo.

- **Objetivos Específicos:**
    - Configurar un entorno de desarrollo que permita la compilación y modificación del kernel de Linux.
    - Descargar y compilar el código fuente del kernel de Linux desde su repositorio oficial.
    - Modificar el kernel para personalizar elementos como el nombre del sistema y agregar mensajes personalizados
      durante el arranque.
    - Desarrollar módulos del kernel que permitan obtener y mostrar estadísticas del sistema, como el uso de CPU,
      memoria y almacenamiento.
    - Implementar nuevas llamadas al sistema para la captura de instantáneas de la memoria, el monitoreo del uso de las
      llamadas al sistema y la recopilación de estadísticas de I/O.

## **Configuración del Entorno**

Para configurar y compilar el kernel modificado, se deben seguir los pasos detallados a continuación:

1. **Instalación de herramientas esenciales:**
   Se requiere instalar las dependencias necesarias para la compilación del kernel. En una terminal, ejecutar el
   siguiente comando:

   ```bash
   sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev
   ```

2. **Copia de la configuración actual del sistema:**
   Para preservar la funcionalidad del sistema actual, se debe copiar la configuración activa del kernel en uso. Esto se
   logra con el siguiente comando:

   ```bash
   cp /boot/config-$(uname -r) .config
   ```

3. **Actualización de la configuración del kernel:**
   Para integrar las nuevas opciones del kernel descargado, se utiliza el siguiente comando, el cual pedirá confirmar o
   modificar configuraciones nuevas:

   ```bash
   make oldconfig
   ```

4. **Deshabilitación de claves del sistema:**
   En caso de ser necesario, se pueden deshabilitar las claves de confianza del sistema con los comandos:

   ```bash
   scripts/config --disable SYSTEM_TRUSTED_KEYS
   scripts/config --disable SYSTEM_REVOCATION_KEYS
   ```

5. **Compilación del kernel y sus módulos:**
   Para compilar el kernel y los módulos asociados, se deben ejecutar los siguientes comandos en orden:

    - Compilar el kernel:

      ```bash
      make -j$(nproc)
      ```

    - Instalar los módulos del kernel:

      ```bash
      make modules_install
      ```

    - Instalar los encabezados del kernel:

      ```bash
      make headers_install
      ```

    - Instalar el kernel:

      ```bash
      make install
      ```

6. **Reinicio del sistema:**
   Una vez instalado el kernel, se debe reiniciar el sistema para aplicar los cambios. Al arrancar el sistema,
   seleccionar el kernel personalizado desde el gestor de arranque.

## **Descripción de Modificaciones en el Kernel**

1. **Personalización del Nombre del Sistema**
   Para modificar el nombre del sistema, es necesario editar el archivo `uts.h`, ubicado en la ruta `/include/linux/`.
   En este archivo, se encuentra la línea correspondiente al nombre del sistema definido como `UTS_SYSNAME`.

   La modificación consiste en cambiar el valor de esta línea por el nombre personalizado deseado. Por ejemplo:

    ```c
    #define UTS_SYSNAME "CustomKernel"
    ```

   Después de realizar esta modificación, se debe recompilar el kernel. Una vez compilado e instalado, la
   personalización se puede verificar utilizando los comandos:

    ```bash
    uname -a
    uname -r
    ```

2. **Adición de un Mensaje de Bienvenida**
   Para agregar un mensaje de bienvenida al kernel, se debe modificar el archivo `main.c`, ubicado en la ruta `/init/`.
   En este archivo, buscar la función `start_kernel`, que se encarga de las inicializaciones al iniciar el kernel.

   Dentro de la función `start_kernel`, localizar la línea que contiene:

    ```c
    pr_notice("%s", linux_banner);
    ```

   Debajo de esta línea, agregar el siguiente código para incluir el mensaje de bienvenida:

    ```c
    printk(KERN_INFO "¡Bienvenido al kernel USAC! 😎\n");
    ```

   Después de realizar esta modificación, se debe recompilar el kernel. El mensaje agregado será visible durante el
   arranque del sistema o al consultar el registro de mensajes con el comando:

    ```bash
    dmesg | grep "¡Bienvenido al kernel USAC"
    ```

## **Documentación de la llamada al sistema `capture_memory_snapshot`**

### **Propósito**

La llamada al sistema `capture_memory_snapshot` permite capturar el estado de la memoria del sistema en un instante
determinado. Esto incluye información como memoria total, memoria libre, buffers, caché, swap total, y swap libre. Es
útil para analizar el uso de memoria, identificar posibles problemas de fragmentación y realizar un monitoreo detallado
del sistema.

### **Diseño**

#### **Definición**

```c
SYSCALL_DEFINE2(capture_memory_snapshot, void __user *, buf, size_t, len);
```

#### **Parámetros**

1. **`buf`**:
   Puntero al espacio de usuario donde se almacenará el snapshot de memoria. Este buffer debe ser lo suficientemente
   grande para contener la información generada.

2. **`len`**:
   Tamaño del buffer proporcionado, en bytes. Se utiliza para validar que el buffer sea suficiente para la operación.

#### **Valor de Retorno**

- **`0`**: Indica que la operación se realizó con éxito.
- **`-EINVAL`**: Se retorna si el buffer proporcionado es demasiado pequeño.
- **`-EFAULT`**: Indica que hubo un fallo al copiar los datos al espacio de usuario.

### **Código Implementado**

```c
SYSCALL_DEFINE2(capture_memory_snapshot, void __user *, buf, size_t, len) {
	struct sysinfo memory_information;
	char snapshot[256]; // En este buffer se almacenará el snapshot que se enviará al espacio de usuario.
	int user_return; // Variable para retornar el snapshot al espacio de usuario.

	si_meminfo(&memory_information);

	// Formato del snapshot.
	snprintf(
		snapshot, sizeof(snapshot),
		"Memoria Total: %lu kB\n"
		"Memory Libre: %lu kB\n"
		"Buffers: %lu kB\n"
		"Memoria Cacheada: %lu kB\n"
		"Swap Total: %lu kB\n"
		"Swap Libre: %lu kB\n",
		memory_information.totalram << (PAGE_SHIFT - 10),
		memory_information.freeram << (PAGE_SHIFT - 10),
		memory_information.bufferram << (PAGE_SHIFT - 10),
		global_node_page_state(NR_FILE_PAGES) << (PAGE_SHIFT - 10),
		memory_information.totalswap << (PAGE_SHIFT - 10),
		memory_information.freeswap << (PAGE_SHIFT - 10)
	);

	if (len < strlen(snapshot) + 1)
		return -EINVAL;

	user_return = copy_to_user(buf, snapshot, strlen(snapshot) + 1);
	if (user_return)
		return -EFAULT;

	return 0;
}
```

### **Ejemplo de Uso**

El siguiente ejemplo muestra cómo realizar una llamada a `capture_memory_snapshot` desde un programa de espacio de
usuario.

#### Código del Usuario

```c
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SYSCALL_NUM 462

int main() {
    char buffer[512] = {0};

    const long user_return = syscall(SYSCALL_NUM, buffer, sizeof(buffer));

    if (user_return == 0) {
        printf("Snapshot de memoria:\n%s\n", buffer);
    } else {
        printf("Error al ejecutar la syscall: %s\n", strerror(errno));
    }

    return 0;
}
```

#### Compilación y Ejecución

Para compilar y ejecutar el programa:

```bash
gcc -o capture_memory_snapshot capture_memory_snapshot.c
./capture_memory_snapshot
```

#### Salida Esperada

```plaintext
Snapshot de memoria:
Memoria Total: 8138788 kB
Memory Libre: 354680 kB
Buffers: 106320 kB
Memoria Cacheada: 1449960 kB
Swap Total: 0 kB
Swap Libre: 0 kB
```

## **Documentación de la llamada al sistema `track_syscall_usage`**

### **Propósito**

La llamada al sistema `track_syscall_usage` permite obtener información sobre el uso de ciertas llamadas al sistema
específicas, como `open`, `read`, `write` y `fork`. Esta información incluye cuántas veces se han ejecutado estas
syscalls desde que se inició el sistema. Es útil para auditorías, monitoreo del sistema y análisis de rendimiento.

### **Diseño**

#### **Definición**

```c
SYSCALL_DEFINE3(track_syscall_usage, const char __user *, syscall_name, char __user *, buffer, size_t, len);
```

#### **Parámetros**

1. **`syscall_name`**:
   Nombre de la syscall que se desea consultar (`"open"`, `"read"`, `"write"`, `"fork"`). Este parámetro se pasa desde
   el espacio de usuario.
2. **`buffer`**:
   Puntero al espacio de usuario donde se almacenará el resultado.
3. **`len`**:
   Tamaño del buffer proporcionado, en bytes. Esto asegura que el buffer sea lo suficientemente grande para almacenar
   los datos generados.

#### **Valor de Retorno**

- **`0`**: Indica que la operación se realizó con éxito.
- **`-EINVAL`**: Se retorna si se proporcionó un nombre de syscall no válido o si el tamaño del buffer es insuficiente.
- **`-EFAULT`**: Indica que hubo un fallo al copiar los datos al espacio de usuario.

### **Código Implementado**

```c
/* Custom global variables used in the usage tracking syscall. */
atomic_t open_count = ATOMIC_INIT(0);
atomic_t read_count = ATOMIC_INIT(0);
atomic_t write_count = ATOMIC_INIT(0);
atomic_t fork_count = ATOMIC_INIT(0);

EXPORT_SYMBOL(open_count);
EXPORT_SYMBOL(read_count);
EXPORT_SYMBOL(write_count);
EXPORT_SYMBOL(fork_count);

SYSCALL_DEFINE3(track_syscall_usage, const char __user *, syscall_name, char __user *, buffer, size_t, len) {
    char name[16]; // Este buffer contendrá el nombre de la syscall solicitada.
    char output[128]; // Este buffer contendrá la salida que se enviará al espacio de usuario.
    int user_return; // Variable para retornar el snapshot al espacio de usuario.

    printk(KERN_INFO "track_syscall_usage: syscall invoked\n");

    // Copiar el nombre de la syscall desde el espacio de usuario.
    if (copy_from_user(name, syscall_name, sizeof(name))) {
        printk(KERN_ERR "track_syscall_usage: copy_from_user failed\n");

        return -EFAULT;
    }

    printk(KERN_INFO "track_syscall_usage: syscall_name copied: %s\n", name);

    // Obtener la salida según la syscall solicitada.
    if (strcmp(name, "open") == 0) {
        // printk(KERN_INFO "track_syscall_usage: open count is %d\n", atomic_read(&open_count));
        snprintf(output, sizeof(output), "open called %d times\n", atomic_read(&open_count));
    } else if (strcmp(name, "read") == 0) {
        // printk(KERN_INFO "track_syscall_usage: read count is %d\n", atomic_read(&read_count));
        snprintf(output, sizeof(output), "read called %d times\n", atomic_read(&read_count));
    } else if (strcmp(name, "write") == 0) {
        // printk(KERN_INFO "track_syscall_usage: write count is %d\n", atomic_read(&write_count));
        snprintf(output, sizeof(output), "write called %d times\n", atomic_read(&write_count));
    } else if (strcmp(name, "fork") == 0) {
        // printk(KERN_INFO "track_syscall_usage: fork count is %d\n", atomic_read(&fork_count));
        snprintf(output, sizeof(output), "fork called %d times\n", atomic_read(&fork_count));
    } else {
        printk(KERN_ERR "track_syscall_usage: invalid syscall name: %s\n", name);

        return -EINVAL;
    }

    if (len < strlen(output) + 1) {
        printk(KERN_ERR "track_syscall_usage: buffer size too small\n");

        return -EINVAL;
    }

    user_return = copy_to_user(buffer, output, strlen(output) + 1);
    if (user_return) {
        printk(KERN_ERR "track_syscall_usage: copy_to_user failed\n");

        return -EFAULT;
    }

    printk(KERN_INFO "track_syscall_usage: syscall completed successfully\n");

    return 0;
}
```

### **Ejemplo de Uso**

El siguiente ejemplo muestra cómo utilizar la syscall `track_syscall_usage` desde un programa de espacio de usuario.

#### Código del Usuario

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SYSCALL_NUM 463

int main() {
    char syscall_name[16];
    char buffer[128];

    // Solicitar contador para "open".
    strncpy(syscall_name, "open", sizeof(syscall_name));

    int user_return = syscall(SYSCALL_NUM, syscall_name, buffer, sizeof(buffer));
    if (user_return < 0) {
        perror("fallo en la llamada al sistema (open)");

        return 1;
    }

    printf("Estadísticas de uso de llamadas al sistema: %s\n", buffer);

    // Solicitar contador para "read".
    strncpy(syscall_name, "read", sizeof(syscall_name));

    user_return = syscall(SYSCALL_NUM, syscall_name, buffer, sizeof(buffer));
    if (user_return < 0) {
        perror("fallo en la llamada al sistema (read)");

        return 1;
    }

    printf("Estadísticas de uso de llamadas al sistema: %s\n", buffer);

    // Solicitar contador para "write".
    strncpy(syscall_name, "write", sizeof(syscall_name));

    user_return = syscall(SYSCALL_NUM, syscall_name, buffer, sizeof(buffer));
    if (user_return < 0) {
        perror("fallo en la llamada al sistema (write)");

        return 1;
    }

    printf("Estadísticas de uso de llamadas al sistema: %s\n", buffer);

    // Solicitar contador para "fork".
    strncpy(syscall_name, "fork", sizeof(syscall_name));

    user_return = syscall(SYSCALL_NUM, syscall_name, buffer, sizeof(buffer));
    if (user_return < 0) {
        perror("fallo en la llamada al sistema (fork)");

        return 1;
    }

    printf("Contadores de uso de llamadas al sistema: %s\n", buffer);

    return 0;
}
```

#### Compilación y Ejecución

Para compilar y ejecutar el programa:

```bash
gcc -o track_syscall_usage track_syscall_usage.c
./track_syscall_usage
```

#### Salida Esperada

```plaintext
Estadísticas de uso de llamadas al sistema: open called 258795 times
Estadísticas de uso de llamadas al sistema: read called 187596 times
Estadísticas de uso de llamadas al sistema: write called 71373 times
Estadísticas de uso de llamadas al sistema: fork called 8 times
```

## **Documentación de la llamada al sistema `get_io_throttle`**

### **Propósito**

El módulo `get_io_throttle` permite a los usuarios obtener información estadística sobre el uso de I/O de un proceso
específico en el sistema, identificado por su PID. Este módulo facilita el análisis del comportamiento de entrada/salida
de aplicaciones, mostrando detalles clave como la cantidad de bytes leídos y escritos, número de llamadas de lectura y
escritura realizadas, bytes leídos desde disco, bytes escritos a disco, y bytes de escritura cancelados.

### **Diseño**

#### **Definición**

```c
SYSCALL_DEFINE2(get_io_throttle, pid_t, pid, struct io_stats __user *, stats);
```

#### **Parámetros**

- `pid`: Identificador del proceso para el cual se desean las estadísticas.
- `stats`: Estructura definida en el espacio de usuario donde se almacenará la información recopilada.

#### **Valor de Retorno**

- **0**: Indica que la operación se realizó con éxito.
- **-ESRCH**: El PID proporcionado no corresponde a ningún proceso en ejecución.
- **-EFAULT**: Ocurrió un error al copiar los datos al espacio de usuario.

### **Código Implementado**

```c
struct io_stats {
	u64 rchar;
	u64 wchar;
	u64 syscr;
	u64 syscw;
	u64 read_bytes;
	u64 write_bytes;
	u64 cancelled_write_bytes;
};

SYSCALL_DEFINE2(get_io_throttle, pid_t, pid, struct io_stats __user *, stats) {
	struct task_struct *task;
	struct io_stats kernel_stats;

	rcu_read_lock(); // Protege contra cambios concurrentes mientras se busca la tarea.
	task = pid_task(find_vpid(pid), PIDTYPE_PID); // Encuentra la tarea asociada al PID.
	rcu_read_unlock();

	// Si no se encuentra la tarea, retorna un error notificando que no existe la tarea.
	if (!task)
		return -ESRCH;

	// Se verifica si el usuario tiene permisos suficientes para acceder al proceso objetivo.
	if (!ptrace_may_access(task, PTRACE_MODE_READ_REALCREDS))
		return -EACCES;

	// Llena la estructura con estadísticas de I/O que será retornada al usuario.
	kernel_stats.rchar = task->ioac.rchar;
	kernel_stats.wchar = task->ioac.wchar;
	kernel_stats.syscr = task->ioac.syscr;
	kernel_stats.syscw = task->ioac.syscw;
	kernel_stats.read_bytes = task->ioac.read_bytes;
	kernel_stats.write_bytes = task->ioac.write_bytes;
	kernel_stats.cancelled_write_bytes = task->ioac.cancelled_write_bytes;

	if (copy_to_user(stats, &kernel_stats, sizeof(kernel_stats)))
		return -EFAULT;

	return 0;
}
```

### **Ejemplo de Uso**

El siguiente ejemplo muestra cómo realizar una llamada a `get_io_throttle` desde un programa de espacio de usuario.

#### Código del Usuario

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct io_stats {
    unsigned long long rchar;
    unsigned long long wchar;
    unsigned long long syscr;
    unsigned long long syscw;
    unsigned long long read_bytes;
    unsigned long long write_bytes;
    unsigned long long cancelled_write_bytes;
};

#define SYSCALL_NUM 464

/*
 * Con "argc" se cuenta la cantidad de argumentos pasados al programa. El primer argumento es el nombre del programa.
 * Con "argv" se almacenan los argumentos pasados al programa en forma de arreglo de cadenas.
 */
int main(const int argc, char *argv[]) {
    struct io_stats stats;

    // Si no se pasó un PID como argumento, se explica cómo usar el programa.
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <PID>\n", argv[0]);

        return 1;
    }

    const pid_t pid = atoi(argv[1]); // NOLINT(*-err34-c)

    if (syscall(SYSCALL_NUM, pid, &stats) == 0) {
        printf("Estadísticas de I/O para el PID %d:\n", pid);
        printf("  Bytes leídos: %llu\n", stats.rchar);
        printf("  Bytes escritos: %llu\n", stats.wchar);
        printf("  Llamadas a read: %llu\n", stats.syscr);
        printf("  Llamadas a write: %llu\n", stats.syscw);
        printf("  Bytes leídos del disco: %llu\n", stats.read_bytes);
        printf("  Bytes escritos al disco: %llu\n", stats.write_bytes);
        printf("  Bytes de escrituras canceladas: %llu\n", stats.cancelled_write_bytes);
    } else {
        perror("fallo en la llamada al sistema");
    }

    return 0;
}
```

#### Compilación y Ejecución

Compilar el programa con:

```bash
gcc -o get_io_throttle get_io_throttle.c
./get_io_throttle <pid>
```

#### Salida Esperada

```plaintext
Estadísticas de I/O para el PID 2407:
  Bytes leídos: 160646
  Bytes escritos: 5030
  Llamadas a read: 374
  Llamadas a write: 225
  Bytes leídos del disco: 57344
  Bytes escritos al disco: 0
  Bytes de escrituras canceladas: 0
```

### **Documentación del módulo `system_stats`**

### **Propósito**

El módulo `system_stats` fue desarrollado para recopilar y mostrar estadísticas clave del sistema en tiempo real.
Incluye información sobre:

1. Uso de memoria.
2. Uso de CPU.
3. Uso de almacenamiento de disco para la partición raíz (`/`).

Estas estadísticas son útiles para monitorear el rendimiento del sistema y diagnosticar problemas relacionados con
recursos.

### **Diseño**

#### **Definición**

El módulo registra una entrada en el sistema de archivos `/proc` bajo el nombre `system_stats`. Los usuarios pueden leer
esta entrada para obtener las estadísticas del sistema.

#### **Estadísticas Mostradas**

1. **Memoria**:
    - **Total**: Memoria total disponible en el sistema.
    - **Usada**: Memoria total menos la memoria libre.
    - **Libre**: Memoria disponible para nuevas aplicaciones y procesos.

2. **CPU**:
    - **Modo usuario**: Tiempo que la CPU ha pasado ejecutando procesos en modo usuario.
    - **Modo sistema**: Tiempo dedicado a tareas del kernel.
    - **Modo inactivo**: Tiempo en el que la CPU ha estado inactiva.

3. **Disco**:
    - **Total**: Espacio total disponible en la partición raíz (`/`).
    - **Libre**: Espacio aún disponible para ser utilizado.

### **Código Implementado**

El módulo sigue el patrón típico de un módulo del kernel:

1. **Inicialización**: Se crea una entrada en `/proc` usando `proc_create`.
2. **Lectura de estadísticas**: Al leer la entrada, se ejecuta la función `proc_show`, que recopila y muestra las
   estadísticas del sistema.
3. **Liberación**: Al descargar el módulo, se elimina la entrada de `/proc`.

El código completo del módulo es:

```c
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/path.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/vmstat.h>

#define PROC_NAME "system_stats"

MODULE_LICENSE("GPL");

MODULE_DESCRIPTION("Módulo de estadísticas del sistema");

MODULE_AUTHOR("Luis César Lizama Quiñónez");

static int proc_show(struct seq_file *m, void *v) {
    struct sysinfo system_information;
    struct kstatfs stat;
    struct path path;

    // Estadísticas de memoria.
    si_meminfo(&system_information);
    unsigned long total = system_information.totalram << (PAGE_SHIFT - 10); // Se convierten en KB.
    unsigned long free = system_information.freeram << (PAGE_SHIFT - 10); // Se convierten en KB.
    unsigned long used = total - free;

    seq_printf(m, "Uso de Memoria:\n");
    seq_printf(m, "  Total: %lu KB\n", total);
    seq_printf(m, "  Usada: %lu KB\n", used);
    seq_printf(m, "  Libre: %lu KB\n\n", free);

    // Estadísticas de CPU.
    seq_printf(m, "Uso de CPU:\n");
    seq_printf(m, "  Usuario: %llu\n", kcpustat_cpu(0).cpustat[CPUTIME_USER]);
    seq_printf(m, "  Sistema: %llu\n", kcpustat_cpu(0).cpustat[CPUTIME_SYSTEM]);
    seq_printf(m, "  Inactivo: %llu\n\n", kcpustat_cpu(0).cpustat[CPUTIME_IDLE]);

    // Estadísticas de almacenamiento.
    if (kern_path("/", LOOKUP_FOLLOW, &path) == 0) {
        if (!vfs_statfs(&path, &stat)) {
            seq_printf(m, "Uso del Disco (/):\n");
            seq_printf(m, "  Total: %llu KB\n", stat.f_blocks * stat.f_bsize / 1024);
            seq_printf(m, "  Libre: %llu KB\n", stat.f_bfree * stat.f_bsize / 1024);
        } else {
            seq_printf(m, "Estadísticas del disco no disponibles.\n");
        }
        path_put(&path); // Se libera la ruta después de usarla.
    } else {
        seq_printf(m, "No se pudo obtener la ruta para las estadísticas del disco.\n");
    }

    return 0;
}

static int proc_open(struct inode *inode, struct file *file) {
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open = proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init system_stats_init(void) {
    proc_create(PROC_NAME, 0, NULL, &proc_fops);
    pr_info("Módulo de estadísticas del sistema cargado\n");

    return 0;
}

static void __exit system_stats_exit(void) {
    remove_proc_entry(PROC_NAME, NULL);
    pr_info("Módulo de estadísticas del sistema descargado\n");
}

module_init(system_stats_init);

module_exit(system_stats_exit);
```

### **Ejemplo de Uso**

1. **Compilación del módulo**:
   Se utiliza un `Makefile` estándar para compilar el módulo:

   ```makefile
   obj-m := system_stats.o
   KDIR := /lib/modules/$(shell uname -r)/build
   PWD := $(shell pwd)

   all:
   $(MAKE) -C $(KDIR) M=$(PWD) modules

   clean:
   $(MAKE) -C $(KDIR) M=$(PWD) clean
   ```

   Ejecuta los comandos:

   ```bash
   make
   sudo insmod system_stats.ko
   ```

2. **Consulta de estadísticas**:
   Las estadísticas están disponibles en `/proc/system_stats`:

   ```bash
   cat /proc/system_stats
   ```

   **Salida esperada**:

   ```plaintext
   Uso de Memoria:
     Total: 8138788 KB
     Usada: 354680 KB
     Libre: 7784108 KB

   Uso de CPU:
     Usuario: 10824000000
     Sistema: 4403000000
     Inactivo: 1334545000000

   Uso del Disco (/):
     Total: 65220172 KB
     Libre: 29751392 KB
   ```

3. **Desinstalación del módulo**:

   ```bash
   sudo rmmod system_stats
   ```

## **Pruebas Realizadas**

Se realizaron diversas pruebas para verificar el correcto funcionamiento de las syscalls y módulos implementados en el
kernel. Las pruebas se enfocaron en los siguientes aspectos:

1. **Compilación y carga del kernel**:
    - Cada modificación al kernel fue compilada exitosamente, asegurando que no hubiera errores de sintaxis ni
      conflictos durante la construcción.
    - El sistema se reinició con el nuevo kernel para verificar que las modificaciones no causaran problemas en el
      arranque ni afectaran otras funciones del sistema operativo.

2. **Pruebas con los módulos del kernel**:
    - Se desarrollaron módulos del kernel complementarios que interactúan con las syscalls. Estos módulos fueron
      cargados y descargados dinámicamente usando `insmod` y `rmmod`, sin errores ni bloqueos.
    - Se utilizó `/proc` o `dmesg` para validar la salida generada por los módulos, asegurándose de que reflejara
      correctamente la información proporcionada por las syscalls.

3. **Problemas encontrados y ajustes realizados**:
    - En algunos casos, se detectaron problemas iniciales relacionados con el acceso al espacio de usuario desde el
      kernel. Estos problemas se resolvieron utilizando técnicas como `copy_to_user`.
    - Algunos errores en las dependencias de bibliotecas del kernel fueron corregidos incluyendo encabezados adecuados y
      asegurando que las estructuras necesarias estuvieran correctamente declaradas.

4. **Resultados finales**:
    - Todas las pruebas realizadas confirmaron que las syscalls y módulos funcionaban correctamente, entregando los
      resultados esperados y manejando errores de manera robusta.

## **Desarrollo de Habilidades Blandas**

### **Autogestión del Tiempo**

Dado que el tiempo asignado para completar este proyecto fue de menos de una semana, tuve que organizar cuidadosamente
mis actividades para asegurar la finalización exitosa. Aquí está el cronograma que seguí durante los días del proyecto:

#### **Lunes: Exploración Inicial y Planificación**

El primer día me enfoqué en entender la lógica detrás de las modificaciones del kernel. Revisé documentación, ejemplos
previos y definí las prioridades. También establecí un plan general que incluyó etapas de desarrollo, pruebas y ajustes
finales.

#### **Martes: Configuración del Entorno de Trabajo**

Dediqué este día a configurar el entorno de desarrollo necesario para el kernel. Realicé la instalación del kernel,
ajustes en las herramientas necesarias y validé que todo estuviera funcional. Este proceso incluyó compilar el kernel
base para asegurarme de que el entorno estuviera estable.

#### **Miércoles: Desarrollo de las Syscalls**

Comencé a trabajar en las llamadas al sistema. La primera fue `capture_memory_snapshot`, que requería entender el manejo
de memoria del kernel y trabajar con las estructuras internas. También validé esta syscall con pruebas simples para
asegurar su funcionalidad.

#### **Jueves: Continuación y Pruebas**

El jueves avancé con la implementación de `track_syscall_usage` y realicé pruebas extensas para verificar que los
contadores de llamadas funcionaran correctamente. Aquí encontré varios errores que fueron solucionados revisando las
dependencias y ajustando la lógica.

#### **Viernes: Syscall de I/O**

El viernes trabajé en la syscall `get_io_throttle`, que presentó retos significativos al usar estructuras como
`task_io_accounting`. Esto me llevó a profundizar en cómo Linux gestiona estadísticas de entrada/salida por proceso.
Validé los datos obtenidos para asegurar que fueran precisos y útiles.

#### **Sábado: Ajustes Finales y Documentación**

Este día fue dedicado a integrar todos los cambios, realizar pruebas completas de todas las syscalls y resolver
cualquier inconsistencia restante. También comencé la redacción de la documentación para describir el diseño,
implementación y pruebas realizadas.
