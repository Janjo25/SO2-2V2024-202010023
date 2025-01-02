#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "memory_limiter.h"

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
