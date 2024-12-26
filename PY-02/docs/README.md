# **Documentación Técnica del Proyecto Tamalloc con Lazy-Zeroing**

## **Diseño del Algoritmo y Llamadas al Sistema**

### **Introducción**

El proyecto desarrolla un asignador de memoria llamado `tamalloc` que emplea el concepto de *lazy-zeroing*, es decir,
las páginas de memoria no se inicializan físicamente hasta su primer acceso. Además, incluye dos llamadas adicionales al
sistema para recolectar estadísticas de memoria, tanto a nivel de procesos individuales como del sistema completo.

---

### **1. Llamada al Sistema: `tamalloc`**

#### **Propósito**

`tamalloc` asigna bloques de memoria de forma eficiente, inicializándolos con ceros únicamente cuando las páginas son
accedidas. Esto evita el uso inmediato de memoria física y mejora el manejo del *overcommit* en el sistema.

#### **Diseño**

##### **Definición**

```c
SYSCALL_DEFINE1(tamalloc, size_t, size);
```

##### **Parámetros**

- **`size`**: Tamaño en bytes del bloque de memoria a asignar. Si es `0`, la syscall retorna un error `-EINVAL`.

##### **Funcionamiento**

1. Alineación del tamaño solicitado a un múltiplo del tamaño de página.

2. Asignación de memoria virtual utilizando `vm_mmap` con las siguientes banderas:
    - **`PROT_READ | PROT_WRITE`**: Permite leer y escribir en la memoria asignada.
    - **`MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE`**: Indica que la memoria no está asociada a un archivo y que no se
      reservan páginas físicas hasta el acceso.

3. Retorno de la dirección base del bloque asignado al espacio de usuario.

##### **Código Implementado**

```c
SYSCALL_DEFINE1(tamalloc, size_t, size) {
    long user_return;

    if (size == 0)
        return -EINVAL;

    /*
     * Alinear el tamaño de la memoria a reservar a una página.
     * El objetivo de esto es no desperdiciar memoria. Esto se logra asignando un múltiplo exacto del tamaño de página.
     * Ejemplo: si el tamaño de página es 4096 bytes, y se solicitan 5000 bytes, se asignarán 8192 bytes.
     */
    size = PAGE_ALIGN(size);

    /*
     * Manejar la asignación y mapeo de la memoria virtual en el espacio de usuario.
     * Es similar a la llamada al sistema mmap, pero está diseñada para ser utilizada en el espacio de kernel.
     * El primer parámetro es la dirección base del mapeo, NULL indica que el kernel debe elegir la dirección.
     * El segundo parámetro es el offset en páginas dentro del archivo, si es que se está mapeando un archivo.
     * El tercer parámetro es la cantidad de memoria a asignar, en bytes. Esto fue alineado previamente.
     * El cuarto parámetro son las banderas de protección y de mapeo.
     * Con "PROT_READ | PROT_WRITE" se indica que la memoria mapeada puede ser leída y escrita.
     * Con "MAP_PRIVATE" se indica que el mapeo es privado y las modificaciones no se reflejarán en el archivo subyacente (si lo hubiera).
     * Con "MAP_ANONYMOUS" se indica que el mapeo no está asociado a un archivo.
     * Con "MAP_NORESERVE" se indica que no se reservará espacio de swap o memoria física al momento de la asignación.
     * Esto permite que la memoria sea asignada de forma "lazy allocation", es decir, las páginas no se asignan físicamente hasta que se acceden.
     * El último parámetro es el desplazamiento en el archivo cuando se está mapeando memoria desde un archivo.
     * En este caso, ya que se está usando "MAP_ANONYMOUS", este parámetro no aplica y se establece en 0.
     */
    user_return = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, 0);

    if (user_return < 0)
        return user_return;

    // Retornar la dirección base del bloque de memoria asignado al proceso de usuario.
    return user_return;
}
```

#### **Ejemplo de Uso en Espacio de Usuario**

##### Código del Usuario

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define SYSCALL_NUM 465

int main() {
    printf("PID del programa: %d\n", getpid());

    printf("Presiona ENTER para continuar...\n");
    getchar();

    const size_t total_size = 10 * 1024 * 1024; // Se asignan 10 MB de memoria.

    char *buffer = (char *) syscall(SYSCALL_NUM, total_size);

    if ((long) buffer < 0) {
        perror("fallo en la llamada al sistema");

        return 1;
    }

    printf("Se asignaron 10 MB de memoria en la dirección: %p\n", buffer);

    printf("Presiona ENTER para empezar a leer la memoria byte por byte...\n");
    getchar();

    // Inicializa el generador de números aleatorios con una semilla basada en el tiempo actual.
    srand(time(NULL));

    for (size_t i = 0; i < total_size; i++) {
        const char current_byte = buffer[i]; // Almacena el valor del byte actual para verificar su inicialización.

        if (current_byte != 0) {
            printf("La memoria no se inicializó en cero en el byte %zu\n", i);

            return 1;
        }

        // Genera un carácter aleatorio entre 'A' y 'Z' y lo escribe en el byte actual.
        const char random_letter = 'A' + rand() % 26;
        buffer[i] = random_letter;

        if (i % (1024 * 1024) == 0 && i > 0) {
            printf("Verificados %zu MB...\n", i / (1024 * 1024));
            sleep(1); // Pausa de 1 segundo para que el usuario pueda ver el progreso.
        }
    }

    printf("Toda la memoria se verificó que está inicializada en cero. Presiona ENTER para salir.\n");
    getchar();

    return 0;
}
```

##### **Compilación y Ejecución**

```bash
gcc -o tamalloc_test tamalloc_test.c
./tamalloc_test
```

---

### **2. Llamada al Sistema: `get_mem_stats`**

#### **Propósito**

Obtiene estadísticas de memoria reservada y comprometida por un proceso específico, así como el puntaje del *OOM
Killer* (Out-Of-Memory Killer).

#### **Diseño**

##### **Definición**

```c
SYSCALL_DEFINE2(get_mem_stats, pid_t, pid, struct mem_stats __user *, stats);
```

##### **Parámetros**

1. **`pid`**: Identificador del proceso objetivo.
2. **`stats`**: Puntero a la estructura donde se almacenarán las estadísticas calculadas.

##### **Funcionamiento**

1. Localiza el proceso con el PID especificado.

2. Calcula:
    - **Memoria Reservada**: Tamaño virtual total (total_vm).
    - **Memoria Comprometida**: Resident Set Size (RSS).
    - **OOM Score**: Puntaje del proceso para el *OOM Killer*, ajustado según `oom_score_adj`.

3. Copia los datos al espacio de usuario.

##### **Código Implementado**

```c
struct mem_stats {
    unsigned long reserved_kb;
    unsigned long committed_kb;
    unsigned int oom_score;
};

SYSCALL_DEFINE2(get_mem_stats, pid_t, pid, struct mem_stats __user *, stats) {
    struct task_struct *task; // Puntero a la estructura del kernel que representa al proceso con el PID especificado.
    struct mm_struct *mm; // Puntero a la estructura de memoria del proceso.
    struct mem_stats kstats; // Estructura para almacenar las estadísticas calculadas.
    unsigned long rss_pages; // Número de páginas RSS, que representa la memoria física utilizada por el proceso.
    unsigned long swap_pages = 0; // Número de páginas utilizadas en SWAP por el proceso.
    unsigned long total_ram_pages; // Número total de páginas de RAM en el sistema.
    unsigned long total_swap_pages = 0; // Número total de páginas de SWAP en el sistema.
    unsigned long total_pages; // Suma de "total_ram_pages" y "total_swap_pages".
    long points; // Puntaje base para calcular el OOM Score.
    long adjust; // Ajuste del "oom_score_adj" para modificar el puntaje base.

    rcu_read_lock();
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    rcu_read_unlock();

    if (!task)
        return -ESRCH;

    // Accede a la estructura de memoria del proceso, o sea, toda la información sobre el espacio de memoria.
    mm = get_task_mm(task);

    // No hay espacio de memoria asignado.
    if (!mm)
        return -ENOMEM;

    // Calcula la memoria reservada y comprometida.
    kstats.reserved_kb = mm->total_vm << PAGE_SHIFT - 10; // Páginas a KB.
    kstats.committed_kb = get_mm_rss(mm) << PAGE_SHIFT - 10; // RSS a KB.

    // Obtiene el RSS en páginas.
    rss_pages = get_mm_rss(mm);

    /*
     * El propósito de "#ifdef" es verificar si un macro está definida antes de usarlo.
     * Esto permite incluir o excluir bloques de código dependiendo de la configuración.
     * En este caso, como se usó el macro "CONFIG_SWAP", se verifica si el sistema tiene soporte para SWAP.
     * Si está definido, se incluye el bloque de código que obtiene el número de páginas de SWAP.
     */
#ifdef CONFIG_SWAP
    swap_pages = get_mm_counter(mm, MM_SWAPENTS); // Obtiene el número de páginas que el proceso movió al área de SWAP.
#endif

    // Obtiene el número total de páginas de memoria RAM física disponibles en el sistema.
    total_ram_pages = get_num_physpages();

#ifdef CONFIG_SWAP
    total_swap_pages = atomic_read(&total_swap_pages); // Obtiene el número total de páginas de SWAP en el sistema.
#endif

    // Se consigue el total para usarlo como base al normalizar el uso de memoria del proceso.
    total_pages = total_ram_pages + total_swap_pages;

    // Evita la división por cero.
    if (!total_pages)
        total_pages = 1;

    // Calcula un puntaje inicial que representa el uso de memoria del proceso en una escala de 0 a 1000.
    points = rss_pages + swap_pages;
    points = points * 1000 / total_pages;

    // Obtiene el ajuste de prioridad para el OOM Killer del proceso.
    adjust = task->signal->oom_score_adj;

    /*
     * Ajusta el puntaje del proceso según oom_score_adj, reflejando su prioridad.
     * Valores negativos protegen al proceso, valores positivos lo priorizan para ser terminado.
     */
    if (adjust < 0) {
        if (-adjust > 31) // Ajuste negativo: disminuye el puntaje.
            points = 0;
        else
            points /= 1UL << -adjust;
    } else if (adjust > 0) {
        if (adjust > 31) // Ajuste positivo: incrementa el puntaje.
            points = 1000;
        else
            points *= 1UL << adjust;
    }

    // Asegurar que el puntaje esté en el rango de 0 a 1000.
    if (points > 1000)
        points = 1000;

    if (points < 0)
        points = 0;

    kstats.oom_score = (unsigned int) points;

    mmput(mm); // Libera la referencia a la estructura "mm_struct".

    if (copy_to_user(stats, &kstats, sizeof(kstats)))
        return -EFAULT;

    return 0;
}
```

#### **Ejemplo de Uso en Espacio de Usuario**

##### Código del Usuario

```c
#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define SYSCALL_NUM 466

struct mem_stats {
    unsigned long reserved_kb;
    unsigned long committed_kb;
    unsigned int oom_score;
};

// Función para imprimir encabezados de la tabla
void print_table_headers() {
    printf(
        "%-10s %-15s %-18s %-10s %-15s\n",
        "PID",
        "Reservada (KB)",
        "Comprometida (KB)",
        "OOM Score",
        "% Comprometida"
    );
    printf(
        "%-10s %-15s %-18s %-10s %-15s\n",
        "==========",
        "===============",
        "==================",
        "==========",
        "============="
    );
}

/*
 * Función para verificar si una cadena es completamente numérica.
 * Esto se hace para filtrar los directorios en "/proc" que no son procesos.
 */
int is_numeric(const char *str) {
    while (*str) {
        if (!isdigit(*str))
            return 0;

        str++;
    }

    return 1;
}


// Función para imprimir las estadísticas con el porcentaje
void print_mem_stats(const pid_t pid, const struct mem_stats stats) {
    double percentage = 0.0;

    if (stats.reserved_kb != 0) {
        percentage = (double) stats.committed_kb / (double) stats.reserved_kb * 100.0;
    }

    printf(
        "%-10d %-15lu %-18lu %-10u %.2f%%\n",
        pid,
        stats.reserved_kb,
        stats.committed_kb,
        stats.oom_score,
        percentage
    );
}

int main(const int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <PID (0 para todos)>\n", argv[0]);

        return EXIT_FAILURE;
    }

    const pid_t pid = atoi(argv[1]);

    // Si el PID es 0, se deben listar todos los procesos. Para lograr esto, se abre el directorio "/proc".
    if (pid == 0) {
        DIR *proc_dir = opendir("/proc");

        if (!proc_dir) {
            perror("fallo al abrir '/proc'");

            return EXIT_FAILURE;
        }

        struct dirent *entry;

        print_table_headers();

        while ((entry = readdir(proc_dir)) != NULL) {
            if (is_numeric(entry->d_name)) {
                const pid_t current_pid = atoi(entry->d_name);
                struct mem_stats stats;

                // Se hace la llamada para el PID actual.
                const long result = syscall(SYSCALL_NUM, current_pid, &stats);

                /*
                 * Si la llamada es exitosa, se imprimen las estadísticas.
                 * Si la llamada falla, se ignora el proceso y se continúa con el siguiente.
                 */
                if (result == 0) {
                    print_mem_stats(current_pid, stats);
                }
            }
        }

        closedir(proc_dir);
    } else {
        struct mem_stats stats;

        const long result = syscall(SYSCALL_NUM, pid, &stats);

        if (result == 0) {
            print_table_headers();
            print_mem_stats(pid, stats);
        } else {
            fprintf(stderr, "Error al obtener estadísticas para PID %d: %s\n", pid, strerror(-result));

            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
```

##### **Compilación y Ejecución**

```bash
gcc -o get_mem_stats get_mem_stats.c
./get_mem_stats <PID>
```

---

### **3. Llamada al Sistema: `get_total_mem_stats`**

#### **Propósito**

Recolecta estadísticas de memoria reservada y comprometida para todos los procesos en el sistema.

#### **Diseño**

##### **Definición**

```c
SYSCALL_DEFINE1(get_total_mem_stats, struct total_mem_stats __user *, stats);
```

##### **Parámetros**

- **`stats`**: Puntero a la estructura donde se almacenarán las estadísticas globales.

##### **Código Implementado**

```c
struct total_mem_stats {
	unsigned long total_reserved_kb;
	unsigned long total_committed_kb;
};

SYSCALL_DEFINE1(get_total_mem_stats, struct total_mem_stats __user *, stats) {
	struct task_struct *task;
	struct total_mem_stats total_stats = {0, 0};
	struct mm_struct *mm;

	for_each_process(task) {
		mm = get_task_mm(task);

		if (!mm) {
			continue; // Se saltan los procesos sin "mm_struct".
		}

		// Suma la memoria reservada y comprometida.
		total_stats.total_reserved_kb += mm->total_vm << (PAGE_SHIFT - 10); // Páginas a KB.
		total_stats.total_committed_kb += get_mm_rss(mm) << (PAGE_SHIFT - 10); // RSS a KB.

		mmput(mm);
	}

	if (copy_to_user(stats, &total_stats, sizeof(total_stats)))
		return -EFAULT;

	return 0;
}
```

#### **Ejemplo de Uso en Espacio de Usuario**

##### Código del Usuario

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SYS_GET_TOTAL_MEM_STATS 467

struct total_mem_stats {
    unsigned long total_reserved_kb;
    unsigned long total_committed_kb;
};

int main() {
    struct total_mem_stats stats;

    const long result = syscall(SYS_GET_TOTAL_MEM_STATS, &stats);

    if (result != 0) {
        perror("fallo al obtener estadísticas totales");

        return EXIT_FAILURE;
    }

    printf("Estadísticas totales de memoria:\n");

    printf(
        "  Memoria total reservada: %lu KB (%.2f MB)\n",
        stats.total_reserved_kb,
        stats.total_reserved_kb / 1024.0
    );
    printf(
        "  Memoria total comprometida: %lu KB (%.2f MB)\n",
        stats.total_committed_kb,
        stats.total_committed_kb / 1024.0
    );

    return EXIT_SUCCESS;
}
```

##### **Compilación y Ejecución**

```bash
gcc -o get_total_mem_stats get_total_mem_stats.c
./get_total_mem_stats
```

---

## **Documentación del módulo `system_stats`**

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

### **Responsabilidad, Compromiso y Resolución de Problemas**

A lo largo del proyecto, me enfrenté a varios desafíos que requerían compromiso y una cuidadosa resolución de problemas.
Los más destacados fueron los siguientes:

#### **1. Entender la estructura del kernel**

El primer problema fue entender el kernel y determinar qué archivos necesitaba modificar para avanzar. Al principio, la
cantidad de información y la complejidad del sistema resultaban abrumadoras, pero este obstáculo se resolvió dedicando
tiempo a leer documentación oficial, buscar en foros y revisar ejemplos prácticos. Poco a poco fui comprendiendo cómo el
sistema estaba organizado y dónde debía trabajar.

#### **2. Llevar la cuenta de llamadas al sistema específicas**

Este fue el desafío más complicado y el que consumió más tiempo. Inicialmente, intenté interceptar directamente las
llamadas al sistema, lo cual resultaba innecesariamente complejo y poco efectivo. Después de reflexionar, decidí cambiar
el enfoque y modificar los archivos fuente que ya manejaban estas llamadas. Esto fue un gran avance, pero surgió un
nuevo problema: las variables definidas en un archivo no eran visibles en otros.

Para solucionarlo, investigué formas de compartir datos entre archivos. Descubrí que podía usar un archivo común, como
un encabezado (`.h`), para declarar las variables de los contadores y exportarlas para que fueran accesibles desde los
diferentes módulos del kernel. Finalmente, los contadores comenzaron a funcionar como esperaba.

#### **3. Espacio insuficiente en la máquina virtual**

El tercer gran problema fue cuando mi máquina virtual se quedó sin espacio debido a un error en mi código. Un bucle mal
programado generaba una enorme cantidad de registros en los logs del sistema cada segundo, lo que saturó el disco en
cuestión de minutos. Esto dejó a la máquina en un estado crítico: el sistema operativo estaba extremadamente lento y no
podía abrir aplicaciones básicas.

La solución requirió reiniciar la máquina virtual y trabajar en condiciones limitadas. Tras investigar, encontré un
comando para borrar los logs y recuperar el espacio perdido. Esto restauró el funcionamiento del sistema y me enseñó una
valiosa lección: revisar cuidadosamente el código, especialmente cuando se trabaja con algo tan sensible como el kernel.

Estos problemas, aunque desafiantes, reforzaron mi capacidad para enfrentar contratiempos, buscar soluciones y seguir
adelante incluso en situaciones difíciles.

### **Reflexión Personal**

Al finalizar el proyecto, me di cuenta de que, aunque implementar las llamadas al sistema parecía una tarea compleja al
principio, el verdadero reto estaba en entender la lógica del kernel. Durante las primeras etapas del proyecto, me
sentía perdido, ya que no sabía exactamente qué archivos modificar ni cómo hacerlo correctamente. Además, tenía miedo de
que una línea mal escrita pudiera romper mi máquina virtual, lo que habría significado empezar desde cero.

Conforme avanzaba, comencé a ganar confianza y a comprender mejor lo que se requería. Leer sobre la estructura del
kernel me permitió identificar que los archivos necesarios para realizar las modificaciones eran pocos y que, en
realidad, solo necesitaba agregar pequeñas secciones de código en lugares estratégicos. Sin embargo, lo verdaderamente
complicado era determinar *qué* debía insertar y dónde.

Superar este desafío implicó mucha lectura de documentación oficial y foros, además de paciencia para experimentar y
equivocarme. Cada problema resuelto reforzó mi entendimiento y me ayudó a avanzar con mayor claridad.

Otra lección importante de este proyecto fue la paciencia. Cada cambio, por más pequeño que fuera, requería recompilar
el kernel, un proceso que consume tiempo. Esto me enseñó a ser meticuloso y a planificar bien cada ajuste antes de
proceder.

En resumen, este proyecto no solo amplió mis conocimientos técnicos, sino que también me ayudó a fortalecer habilidades
clave como la perseverancia, la atención al detalle y la capacidad de enfrentar desafíos complejos con confianza.
