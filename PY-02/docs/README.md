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

## **Análisis de los Resultados Obtenidos: Memoria Solicitada vs. Memoria Realmente Utilizada**

El experimento realizado con la syscall `tamalloc` permitió observar cómo se comporta el sistema al asignar y utilizar
bloques de memoria. A continuación, se presenta un análisis de los resultados:

1. **Memoria Solicitada:**
    - Durante la ejecución del programa, se solicitaron bloques de memoria de tamaño fijo (por ejemplo, 10 MB) a través
      de la syscall `tamalloc`.
    - Este valor representa la cantidad de memoria virtual asignada al proceso por el kernel.

2. **Memoria Realmente Utilizada:**
    - A través del acceso byte por byte, se activó la asignación diferida (**Lazy Allocation**) del kernel.
    - Se verificó que la memoria asignada inicialmente estaba completamente inicializada en `0`, lo que garantiza la
      consistencia del sistema.
    - Hasta que no se accedió a la memoria, no hubo una asignación física en la RAM.

3. **Relación Solicitada vs. Utilizada:**
    - **Memoria Virtual (Solicitada):** El kernel reserva el espacio virtual inmediatamente tras la llamada a
      `tamalloc`, pero este no representa memoria física real hasta que se accede.
    - **Memoria Física (Utilizada):** La memoria física real (RAM) solo se asigna cuando cada byte es leído o escrito,
      como se demostró al escribir caracteres aleatorios en el bloque.

4. **Resultados Observados:**
    - El sistema optimiza el uso de memoria física mediante asignación diferida, minimizando el impacto de reservar
      grandes bloques.
    - Durante las pruebas, se corroboró que la memoria escrita activa el mecanismo **Copy-on-Write (CoW)**, reutilizando
      páginas existentes cuando es posible.

5. **Conclusión:**
    - La diferencia entre memoria solicitada y utilizada demuestra cómo Linux gestiona eficientemente los recursos
      mediante técnicas como la asignación diferida.
    - Este comportamiento es ideal para sistemas que requieren grandes reservas de memoria virtual sin necesidad
      inmediata de asignación física.

## **Desarrollo de Habilidades Blandas**

### **Autogestión del Tiempo**

Dado que el tiempo asignado para completar este proyecto fue de menos de una semana, tuve que organizar cuidadosamente
mis actividades para asegurar la finalización exitosa. Aquí está el cronograma que seguí durante los días del proyecto:

#### **Viernes: Investigación Inicial**

El primer día se dedicó a comprender los requisitos del proyecto, investigar sobre asignación de memoria con
*lazy-zeroing* y familiarizarse con la estructura del kernel de Linux para syscalls.

#### **Sábado: Implementación de `tamalloc`**

Se comenzó con la implementación de la syscall `tamalloc`, trabajando en la alineación de páginas y el manejo de memoria
virtual bajo demanda. Este proceso incluyó pruebas básicas para asegurar que las páginas se inicializan correctamente al
primer acceso.

#### **Domingo: Finalización y Pruebas de `tamalloc`**

Se completó la implementación de `tamalloc` y se realizaron pruebas extensivas utilizando programas de usuario. También
se ajustaron errores relacionados con la inicialización de páginas y la configuración de banderas de mapeo.

#### **Lunes: Desarrollo de `get_mem_stats`**

Se inició la creación de la syscall `get_mem_stats`, centrada en recolectar estadísticas de memoria por proceso. Esto
incluyó manejar estructuras como `mm_struct` y trabajar con referencias seguras.

#### **Martes: Finalización y Pruebas de `get_mem_stats`**

Se completó la implementación de `get_mem_stats`, realizando pruebas extensivas para asegurar que los datos recolectados
fueran precisos y útiles. También se optimizó el manejo de errores y validaciones.

#### **Miércoles: Implementación de `get_total_mem_stats`**

Se desarrolló la syscall `get_total_mem_stats` para recolectar estadísticas globales del sistema. Esto incluyó iterar
sobre procesos y manejar estructuras compartidas de manera eficiente.

#### **Jueves: Documentación y Validación Final**

El último día se dedicó a redactar la documentación técnica, integrar todos los componentes y realizar pruebas finales
para garantizar el correcto funcionamiento de las tres syscalls.

### **Responsabilidad, Compromiso y Resolución de Problemas**

A lo largo del proyecto, me enfrenté a varios desafíos que requerían compromiso y una cuidadosa resolución de problemas.
Los más destacados fueron los siguientes:

#### **1. Implementar la primera llamada al sistema (`tamalloc`)**

El primer problema fue entender cómo implementar la syscall `tamalloc`. Al principio, no comprendía la teoría detrás de
*lazy-zeroing* ni cómo debía funcionar el algoritmo. Intenté avanzar sin entender del todo el concepto, pero rápidamente
me di cuenta de que no estaba progresando. Esto me llevó a detenerme y dedicar tiempo a ver videos y leer documentación
sobre asignación de memoria en el kernel.

Una vez que entendí la utilidad y los fundamentos teóricos, pude identificar la solución. Resultó ser más sencilla de lo
que pensaba inicialmente: una línea clave de código resolvía el problema. Esta experiencia me enseñó que comprender la
teoría antes de lanzarse a la práctica es esencial para evitar perder tiempo valioso.

#### **2. Obtener estadísticas de todos los procesos en `get_mem_stats`**

Otro reto significativo surgió al implementar la funcionalidad para recolectar estadísticas de todos los procesos cuando
el PID era `0`. No sabía cómo iterar sobre todos los procesos activos de manera eficiente. Para solucionarlo, utilicé
`/proc` como base para identificar procesos válidos recorriendo los directorios numéricos que correspondían a PIDs.

El principal desafío fue manejar de forma segura las llamadas para evitar errores si un proceso terminaba durante la
iteración. Implementé validaciones adicionales utilizando funciones como `opendir` y `readdir`, lo que permitió
recolectar datos con precisión. Este problema me enseñó a aprovechar las herramientas disponibles y a ser metódico en el
manejo de estructuras compartidas.

Estos problemas, aunque desafiantes, reforzaron mis habilidades técnicas y mi capacidad para enfrentar problemas, buscar
soluciones y aprender de cada experiencia.

### **Reflexión Personal**

Al finalizar el proyecto, comprendí que la clave para superar los desafíos técnicos radica en un balance entre la teoría
y la práctica. Inicialmente, la falta de una base teórica sólida me hizo perder tiempo al implementar `tamalloc`, pero
al detenerme para investigar, entendí mejor el concepto de *lazy-zeroing* y pude avanzar con confianza.

Otro aprendizaje importante fue sobre la importancia de la organización y las herramientas del kernel. Implementar la
funcionalidad de estadísticas para todos los procesos usando el PID `0` fue un reto que requirió explorar `/proc` y
utilizar funciones del sistema que desconocía. Este proceso me enseñó a aprovechar mejor los recursos disponibles y
pensar en soluciones creativas.

Cada problema enfrentado me ayudó a reforzar mi capacidad de resolver problemas y a ganar confianza trabajando en
proyectos complejos. Este proyecto no solo amplió mi conocimiento técnico, sino que también fortaleció habilidades como
la paciencia, la organización y la adaptabilidad.
