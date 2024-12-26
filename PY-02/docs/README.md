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
