#ifndef MEMORY_LIMITER_H
#define MEMORY_LIMITER_H

#include <linux/list.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/types.h>

// Estructura para la lista de procesos con límites de memoria.
struct memory_node {
    struct memory_limitation {
        pid_t pid;
        size_t memory_limit;
    } mem_limit;

    struct list_head list;
};

// Estructura para devolver procesos limitados al espacio de usuario.
struct limited_process_user {
    pid_t pid;
    size_t memory_limit;
};

// Declaración externa de la lista global.
extern struct list_head memory_list;

// Declaración externa del spinlock para proteger la lista.
extern spinlock_t memory_list_lock;

// Prototipo de la función para obtener el uso actual de memoria de un proceso. Se implementa en otro archivo.
size_t get_process_memory_usage(struct task_struct *task);

#endif
