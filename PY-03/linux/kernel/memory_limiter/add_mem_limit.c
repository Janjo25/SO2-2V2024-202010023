#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "memory_limiter.h"

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
