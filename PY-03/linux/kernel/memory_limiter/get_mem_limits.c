#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>

#include "memory_limiter.h"

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
