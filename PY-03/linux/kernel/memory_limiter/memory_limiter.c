#include <linux/syscalls.h>

#include "memory_limiter.h"

// Inicializa la lista global.
LIST_HEAD(memory_list);

// Inicializa el spinlock para proteger la lista.
DEFINE_SPINLOCK(memory_list_lock);

// Función para obtener el uso actual de memoria de un proceso. Se declara en otro archivo.
size_t get_process_memory_usage(struct task_struct *task) {
    size_t total = 0;
    struct mm_struct *mm = get_task_mm(task);

    if (mm) {
        total = mm->total_vm << PAGE_SHIFT;
        mmput(mm);
    }

    return total;
}
