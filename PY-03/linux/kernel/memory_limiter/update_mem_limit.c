#include <linux/capability.h>
#include <linux/errno.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "memory_limiter.h"

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
