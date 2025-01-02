# **Documentación Técnica del Proyecto: Limitador de Memoria para Procesos**

## **Diseño del Algoritmo y Llamadas al Sistema**

### **Introducción**

El objetivo principal de este proyecto fue implementar un sistema de limitación de memoria en el kernel de Linux,
permitiendo a los usuarios restringir la cantidad máxima de memoria que ciertos procesos pueden solicitar dinámicamente.
Este sistema fue desarrollado mediante la creación de cuatro syscalls para gestionar las operaciones CRUD de un
limitador de memoria basado en una lista enlazada dentro del espacio del kernel.

---

### **1. Syscall: Agregar un Proceso a la Lista de Limitados**

#### **Propósito**

Permitir que los usuarios con privilegios de administrador agreguen procesos a una lista de procesos limitados,
estableciendo un máximo de memoria que estos procesos pueden solicitar.

#### **Diseño**

##### **Definición**

```c
SYSCALL_DEFINE2(so2_add_memory_limit, pid_t, pid, size_t, limit);
```

##### **Funcionamiento**

1. **Validaciones iniciales**:

    - Verificar que el PID y el límite de memoria son válidos.
    - Asegurarse de que el proceso existe y no está ya en la lista.

2. **Uso del spinlock**:

    - Proteger la lista enlazada durante la inserción de un nuevo nodo.

3. **Creación y adición del nodo**:

    - Utilizar `kmalloc` para asignar memoria al nuevo nodo.
    - Agregar el nodo a la lista enlazada global protegida por un `spinlock`.

4. **Errores posibles**:

    - `-EPERM`: Usuario sin privilegios.
    - `-ESRCH`: Proceso no existe.
    - `-ENOMEM`: Falta de memoria para agregar un nuevo nodo.

##### **Código Implementado**

```c
SYSCALL_DEFINE2(so2_add_memory_limit, pid_t, pid, size_t, limit) {
    struct memory_node *node; // Puntero que representa un proceso con su límite de memoria en la lista.
    struct task_struct *task;
    unsigned long flags; // Variable para guarda el estado de interrupciones para spinlocks en regiones críticas.

    printk(KERN_INFO "Syscall so2_add_memory_limit llamado con PID=%d, límite=%zu bytes\n", pid, limit);

    // Verifica si el usuario que lo ejecuta tiene el permiso CAP_SYS_ADMIN, o sea, si es root.
    if (!capable(CAP_SYS_ADMIN)) {
        printk(KERN_WARNING "so2_add_memory_limit: Permiso denegado para PID=%d\n", pid);

        return -EPERM;
    }

    if (pid <= 0 || limit == 0) {
        printk(KERN_WARNING "so2_add_memory_limit: PID=%d o límite=%zu inválido\n", pid, limit);

        return -EINVAL;
    }

    // Verifica si el proceso existe.
    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (!task) {
        printk(KERN_WARNING "so2_add_memory_limit: Proceso con PID=%d no existe\n", pid);

        return -ESRCH;
    }

    /*
     * Un spinlock es un candado que asegura acceso exclusivo a un recurso compartido en el kernel.
     * Protege la lista "memory_list" de accesos simultáneos y evita interrupciones durante operaciones críticas.
     * Es necesario para modificar "memory_list" de forma segura.
     */
    spin_lock_irqsave(&memory_list_lock, flags);

    // Verifica si el proceso ya está en la lista.
    list_for_each_entry(node, &memory_list, list) {
        if (node->mem_limit.pid == pid) {
            spin_unlock_irqrestore(&memory_list_lock, flags);
            printk(KERN_WARNING "so2_add_memory_limit: PID=%d ya está en la lista\n", pid);

            return -101;
        }
    }

    // Crea un nuevo nodo para el proceso.
    node = kmalloc(sizeof(*node), GFP_KERNEL);

    if (!node) {
        spin_unlock_irqrestore(&memory_list_lock, flags);
        printk(KERN_WARNING "so2_add_memory_limit: kmalloc falló para PID=%d\n", pid);

        return -ENOMEM;
    }

    // Inicializa el nodo recién creado con el PID del proceso y su límite de memoria.
    node->mem_limit.pid = pid;
    node->mem_limit.memory_limit = limit;

    // Agrega el nodo a la lista global.
    list_add(&node->list, &memory_list);
    spin_unlock_irqrestore(&memory_list_lock, flags);

    printk(KERN_INFO "Límite de memoria agregado: PID=%d, Límite=%zu bytes\n", pid, limit);

    return 0;
}
```

---

### **2. Syscall: Obtener Lista de Procesos Limitados**

#### **Propósito**

Permitir a los usuarios consultar la lista de procesos limitados y sus límites de memoria.

#### **Diseño**

##### **Definición**

```c
SYSCALL_DEFINE3(
    so2_get_memory_limits,
    struct memory_limitation __user *, u_processes_buffer,
    size_t, max_entries,
    int __user *, u_processes_returned
);
```

##### **Funcionamiento**

1. **Validaciones iniciales**:

    - Verificar punteros y tamaño del buffer.

2. **Iteración sobre la lista**:

    - Recorrer la lista enlazada protegida por un spinlock.
    - Copiar la información al buffer del kernel y luego al espacio de usuario.

3. **Errores posibles**:

    - `-EINVAL`: Parámetros inválidos.
    - `-EFAULT`: Error al copiar datos al espacio de usuario.

##### **Código Implementado**

```c
SYSCALL_DEFINE3(
    so2_get_memory_limits,
    struct memory_limitation __user *, u_processes_buffer,
    size_t, max_entries,
    int __user *, u_processes_returned
) {
    struct memory_node *node;
    struct limited_process_user *k_buffer; // Buffer en el que se guardará cada nodo de la lista global.
    int count = 0;
    int ret = 0;
    size_t buffer_size;
    unsigned long flags;

    printk(KERN_INFO "Syscall so2_get_memory_limits llamado con max_entries=%zu\n", max_entries);

    if (!u_processes_buffer || !u_processes_returned) {
        printk(KERN_WARNING "so2_get_memory_limits: Puntero NULL proporcionado\n");

        return -EINVAL;
    }

    if (max_entries <= 0) {
        printk(KERN_WARNING "so2_get_memory_limits: max_entries=%zu inválido\n", max_entries);

        return -EINVAL;
    }

    buffer_size = max_entries * sizeof(struct limited_process_user);

    // Asigna espacio en el kernel para copiar los datos.
    k_buffer = kmalloc(buffer_size, GFP_KERNEL);

    if (!k_buffer) {
        printk(KERN_WARNING "so2_get_memory_limits: kmalloc falló\n");

        return -ENOMEM;
    }

    spin_lock_irqsave(&memory_list_lock, flags);

    // Recorre la lista y copia los datos al buffer del kernel.
    list_for_each_entry(node, &memory_list, list) {
        if (count >= max_entries)
            break;

        k_buffer[count].pid = node->mem_limit.pid;
        k_buffer[count].memory_limit = node->mem_limit.memory_limit;

        count++;
    }

    printk(KERN_INFO "so2_get_memory_limits: Recuperadas %d entradas\n", count);

    spin_unlock_irqrestore(&memory_list_lock, flags);

    // Copia los datos al espacio de usuario. Si falla la copia, el programa entra al bloque 'if'.
    if (copy_to_user(u_processes_buffer, k_buffer, count * sizeof(struct limited_process_user))) {
        ret = -EFAULT;
        printk(KERN_WARNING "so2_get_memory_limits: copy_to_user falló\n");

        goto out;
    }

    // Copia el número de procesos escritos al espacio de usuario. Si falla la copia, el programa entra al bloque 'if'.
    if (copy_to_user(u_processes_returned, &count, sizeof(int))) {
        ret = -EFAULT;
        printk(KERN_WARNING "so2_get_memory_limits: copy_to_user para processes_returned falló\n");

        goto out;
    }

out:
    kfree(k_buffer); // Libera el buffer del kernel.

    return ret;
}
```

---

### **3. Syscall: Actualizar el Límite de un Proceso**

#### **Propósito**

Permitir actualizar el límite de memoria de un proceso previamente limitado.

#### **Diseño**

##### **Definición**

```c
SYSCALL_DEFINE2(so2_update_memory_limit, pid_t, pid, size_t, new_limit);
```

##### **Funcionamiento**

1. **Validaciones iniciales**:

    - Verificar que el PID y el nuevo límite son válidos.

2. **Modificación del nodo**:

    - Buscar el nodo en la lista enlazada protegida por un spinlock.
    - Actualizar el límite de memoria.

3. **Errores posibles**:

    - `-EPERM`: Usuario sin privilegios.
    - `-ESRCH`: Proceso no existe.
    - `-102`: Proceso no está en la lista.

##### **Código Implementado**

```c
SYSCALL_DEFINE2(so2_update_memory_limit, pid_t, pid, size_t, new_limit) {
    struct memory_node *node;
    struct task_struct *task;
    unsigned long flags;

    printk(KERN_INFO "Syscall so2_update_memory_limit llamado con PID=%d, new_limit=%zu bytes\n", pid, new_limit);

    if (!capable(CAP_SYS_ADMIN)) {
        printk(KERN_WARNING "so2_update_memory_limit: Permiso denegado para PID=%d\n", pid);

        return -EPERM;
    }

    if (pid <= 0 || new_limit == 0) {
        printk(KERN_WARNING "so2_update_memory_limit: PID=%d o new_limit=%zu inválido\n", pid, new_limit);

        return -EINVAL;
    }

    task = pid_task(find_vpid(pid), PIDTYPE_PID);

    if (!task) {
        printk(KERN_WARNING "so2_update_memory_limit: Proceso con PID=%d no existe\n", pid);

        return -ESRCH;
    }

    spin_lock_irqsave(&memory_list_lock, flags);

    list_for_each_entry(node, &memory_list, list) {
        if (node->mem_limit.pid == pid) {
            node->mem_limit.memory_limit = new_limit; // Actualiza el límite de memoria.
            spin_unlock_irqrestore(&memory_list_lock, flags);
            printk(KERN_INFO "Límite de memoria actualizado: PID=%d, Nuevo Límite=%zu bytes\n", pid, new_limit);

            return 0;
        }
    }

    // Si se llega a este punto, el proceso no está en la lista.
    spin_unlock_irqrestore(&memory_list_lock, flags);
    printk(KERN_WARNING "so2_update_memory_limit: PID=%d no encontrado en memory_list\n", pid);

    return -102;
}
```

---

### **4. Syscall: Remover un Proceso de la Lista**

#### **Propósito**

Permitir eliminar un proceso de la lista de procesos limitados.

#### **Diseño**

##### **Definición**

```c
SYSCALL_DEFINE1(so2_remove_memory_limit, pid_t, pid);
```

##### **Funcionamiento**

1. **Validaciones iniciales**:

    - Verificar que el PID es válido.

2. **Eliminación del nodo**:

    - Buscar y eliminar el nodo correspondiente en la lista enlazada protegida por un spinlock.

3. **Errores posibles**:

    - `-EPERM`: Usuario sin privilegios.
    - `-ESRCH`: Proceso no existe.
    - `-102`: Proceso no está en la lista.

##### **Código Implementado**

```c
SYSCALL_DEFINE1(so2_remove_memory_limit, pid_t, pid) {
    struct memory_node *node;
    unsigned long flags;

    printk(KERN_INFO "Syscall so2_remove_memory_limit llamado con PID=%d\n", pid);

    if (!capable(CAP_SYS_ADMIN)) {
        printk(KERN_WARNING "so2_remove_memory_limit: Permiso denegado para PID=%d\n", pid);

        return -EPERM;
    }

    if (pid <= 0) {
        printk(KERN_WARNING "so2_remove_memory_limit: PID=%d inválido\n", pid);

        return -EINVAL;
    }

    spin_lock_irqsave(&memory_list_lock, flags);

    list_for_each_entry(node, &memory_list, list) {
        if (node->mem_limit.pid == pid) {
            list_del(&node->list); // Elimina el nodo de la lista.
            kfree(node); // Libera la memoria del nodo.

            spin_unlock_irqrestore(&memory_list_lock, flags);

            printk(KERN_INFO "Límite de memoria removido: PID=%d\n", pid);

            return 0;
        }
    }

    // Si se llega a este punto, el proceso no está en la lista.
    spin_unlock_irqrestore(&memory_list_lock, flags);
    printk(KERN_WARNING "so2_remove_memory_limit: PID=%d no encontrado en memory_list\n", pid);

    return -102;
}
```

## **Desarrollo de Habilidades Blandas**

### **Autogestión del Tiempo**

Dado el tiempo limitado para completar este proyecto, se realizó una planificación meticulosa para garantizar el
cumplimiento de los objetivos en menos de una semana. Este fue el cronograma seguido:

#### **Sábado: Investigación Inicial**

El día comenzó con un análisis detallado del enunciado del proyecto. Esto incluyó:

- Identificar los requisitos de las cuatro syscalls.
- Investigar sobre el manejo de listas enlazadas en el kernel de Linux, el uso de spinlocks y cómo trabajar con
  estructuras como `task_struct`.
- Estudiar la documentación de syscalls en Linux y ejemplos de implementación.

#### **Domingo: Implementación de las Primeras Syscalls**

Se procedió con la implementación inicial de las syscalls `so2_add_memory_limit` y `so2_get_memory_limits`:

- Configuración del entorno de desarrollo del kernel.
- Creación de las estructuras necesarias, como `memory_node` y la lista global `memory_list`.
- Implementación de la funcionalidad de agregar procesos con límites de memoria.
- Desarrollo y pruebas preliminares de la syscall para obtener los procesos limitados.

#### **Lunes: Finalización de las Syscalls Iniciales**

Se completaron las pruebas de las dos primeras syscalls:

- Validaciones de entradas y manejo de errores.
- Ajustes en el manejo de la lista enlazada para evitar inconsistencias en concurrencia.
- Verificación de funcionalidad usando programas de usuario.

#### **Martes: Implementación de las Syscalls Restantes**

Se inició la implementación de las syscalls `so2_update_memory_limit` y `so2_remove_memory_limit`:

- Desarrollo de la lógica para buscar y actualizar o eliminar nodos de la lista enlazada.
- Manejo de errores específicos para estas operaciones.
- Se realizaron pruebas básicas para confirmar que los nodos eran modificados o eliminados correctamente.

#### **Miércoles: Pruebas Finales y Ajustes**

Se llevaron a cabo pruebas exhaustivas de las cuatro syscalls:

- Validación de todos los posibles errores especificados en el enunciado.
- Optimización del manejo de memoria y spinlocks.
- Identificación y resolución de errores encontrados durante las pruebas de integración.

#### **Jueves: Migración del Código y Documentación**

Se realizó la migración del código desde un único archivo (`sys.c`) a un diseño modular:

- Creación de archivos individuales para cada syscall y su integración en el kernel.
- Actualización de la tabla de syscalls y ajustes en el `Makefile`.
- Redacción de la documentación técnica, detallando el diseño, implementación y funcionamiento del proyecto.

### **Responsabilidad, Compromiso y Resolución de Problemas**

A lo largo del proyecto, me enfrenté a diversos desafíos que requirieron compromiso, creatividad y una cuidadosa
resolución de problemas. Los más destacados fueron los siguientes:

#### **1. Implementar la Primera Syscall (`so2_add_memory_limit`)**

El primer reto significativo fue implementar la syscall para agregar procesos con límites de memoria. A pesar de tener
experiencia previa trabajando con estructuras como `task_struct`, la implementación inicial no cumplía con los
requisitos del enunciado. Probé múltiples enfoques para iterar sobre los procesos y proteger la lista enlazada con
`spinlocks`, pero siempre surgían inconsistencias o fallos en las pruebas.

Finalmente, con la orientación del auxiliar, entendí que debía seguir un enfoque más estructurado al interceptar ciertas
llamadas internas del kernel, como `do_brk_flags` y `ksys_mmap_pgoff`, para garantizar la asignación y manejo correcto
de memoria. Esto resultó ser clave para resolver el problema y avanzar con confianza en la implementación.

Esta experiencia reforzó la importancia de detenerme a analizar problemas con mayor profundidad, así como la utilidad de
pedir orientación cuando es necesario.

#### **2. Migración del Código desde `sys.c` a un Diseño Modular**

Otro reto significativo fue migrar el código de un único archivo monolítico (`sys.c`) a un diseño modular en múltiples
archivos, como lo exige el estilo de desarrollo del kernel de Linux. Aunque técnicamente parecía sencillo, me enfrenté a
errores de compilación que inicialmente no entendía, como variables globales no declaradas (`memory_list_lock`),
conflictos de nombres y dependencias mal organizadas en el `Makefile`.

El problema más frustrante fue que la implementación funcionaba perfectamente en `sys.c`, pero al dividir el código
comenzaron a surgir fallos que no habían aparecido antes. Esto me obligó a revisar minuciosamente la forma en que las
variables globales y funciones se compartían entre archivos mediante `extern` y a reorganizar las definiciones en un
archivo dedicado (`memory_limiter.c`).

Este desafío me enseñó la importancia de organizar adecuadamente los archivos y mantener una estructura modular desde el
principio. También me ayudó a comprender mejor cómo funcionan las dependencias y los enlaces en el kernel.

### **Reflexión Personal**

Nunca me imaginé manipulando los archivos del kernel, y ahora que lo he hecho, mi respeto por quienes trabajan en
proyectos de código abierto y hacen posible que tengamos un sistema funcional ha crecido enormemente. Trabajar en el
kernel de Linux me permitió ver de cerca el increíble esfuerzo que hay detrás de cada línea de código que compone este
sistema operativo.

El lenguaje C, aunque fascinante, también me resultó desafiante. Comparado con lenguajes modernos, su naturaleza directa
y su relación con el hardware requieren una atención minuciosa. Me sorprendió la habilidad que tienen los
desarrolladores del kernel para manejar múltiples archivos y funciones exclusivas, todo mientras mantienen la
estabilidad y funcionalidad del sistema.

A través de este proyecto, aprendí mucho sobre el funcionamiento interno de Linux. Desde el uso de la terminal hasta la
personalización, siempre me ha encantado trabajar con este sistema operativo, pero comprender cómo se construye y
mantiene a través del esfuerzo colaborativo de una comunidad global ha aumentado mi aprecio. La filosofía de trabajo en
equipo y la apertura para compartir conocimientos es algo que, sinceramente, me inspira.

El curso presentó un grado considerable de dificultad, pero lo que más me afectó fue el tiempo. Cada pequeño avance
requería una enorme cantidad de investigación, lectura, pruebas y errores. Además, estaba el constante miedo de dañar el
kernel, pero, afortunadamente, nunca llegué a hacerlo. Esto me demostró que, con cuidado, paciencia y preparación, soy
capaz de enfrentar tareas complejas y lograrlas.

Este proyecto no solo expandió mi conocimiento técnico, sino que también reforzó en mí valores como la organización, la
perseverancia y el respeto por los detalles. Ahora entiendo mejor lo que significa contribuir a algo más grande que uno
mismo, como lo es el desarrollo de Linux.
