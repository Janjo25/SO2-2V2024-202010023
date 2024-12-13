# **Personalización y Expansión del Kernel de Linux: Guía de Configuración y Modificaciones**

## **Introducción y Objetivos del Proyecto**

**Introducción:**
Este proyecto tiene como objetivo la expansión y personalización del kernel de Linux mediante la incorporación de nuevas
funcionalidades específicas, así como la modificación de comportamientos del sistema. Se tendrá la oportunidad de
trabajar con el núcleo de Linux, configurando un entorno de desarrollo adecuado para la compilación del kernel y
desarrollando módulos personalizados que añaden nuevas funcionalidades al sistema operativo. Al realizar estas
modificaciones, se adquieren conocimientos profundos en programación de sistemas y se entienden los principios internos
de los kernels de los sistemas operativos, todo dentro de un entorno controlado y práctico.

**Objetivos del Proyecto:**

- **Objetivo General:**
  Modificar y personalizar el kernel de Linux para agregar nuevas llamadas al sistema y funcionalidades que permitan una
  mayor interacción y control sobre el sistema operativo.

- **Objetivos Específicos:**
    - Configurar un entorno de desarrollo que permita la compilación y modificación del kernel de Linux.
    - Descargar y compilar el código fuente del kernel de Linux desde su repositorio oficial.
    - Modificar el kernel para personalizar elementos como el nombre del sistema y agregar mensajes personalizados
      durante el arranque.
    - Desarrollar módulos del kernel que permitan obtener y mostrar estadísticas del sistema, como el uso de CPU,
      memoria y almacenamiento.
    - Implementar nuevas llamadas al sistema para la captura de instantáneas de la memoria, el monitoreo del uso de las
      llamadas al sistema y la recopilación de estadísticas de I/O.

## **Configuración del Entorno**

Para configurar y compilar el kernel modificado, se deben seguir los pasos detallados a continuación:

1. **Instalación de herramientas esenciales:**
   Se requiere instalar las dependencias necesarias para la compilación del kernel. En una terminal, ejecutar el
   siguiente comando:

   ```bash
   sudo apt install build-essential libncurses-dev bison flex libssl-dev libelf-dev
   ```

2. **Copia de la configuración actual del sistema:**
   Para preservar la funcionalidad del sistema actual, se debe copiar la configuración activa del kernel en uso. Esto se
   logra con el siguiente comando:

   ```bash
   cp /boot/config-$(uname -r) .config
   ```

3. **Actualización de la configuración del kernel:**
   Para integrar las nuevas opciones del kernel descargado, se utiliza el siguiente comando, el cual pedirá confirmar o
   modificar configuraciones nuevas:

   ```bash
   make oldconfig
   ```

4. **Deshabilitación de claves del sistema:**
   En caso de ser necesario, se pueden deshabilitar las claves de confianza del sistema con los comandos:

   ```bash
   scripts/config --disable SYSTEM_TRUSTED_KEYS
   scripts/config --disable SYSTEM_REVOCATION_KEYS
   ```

5. **Compilación del kernel y sus módulos:**
   Para compilar el kernel y los módulos asociados, se deben ejecutar los siguientes comandos en orden:

    - Compilar el kernel:

      ```bash
      make -j$(nproc)
      ```

    - Instalar los módulos del kernel:

      ```bash
      make modules_install
      ```

    - Instalar los encabezados del kernel:

      ```bash
      make headers_install
      ```

    - Instalar el kernel:

      ```bash
      make install
      ```

6. **Reinicio del sistema:**
   Una vez instalado el kernel, se debe reiniciar el sistema para aplicar los cambios. Al arrancar el sistema,
   seleccionar el kernel personalizado desde el gestor de arranque.

## **Descripción de Modificaciones en el Kernel**

1. **Personalización del Nombre del Sistema**
   Para modificar el nombre del sistema, es necesario editar el archivo `uts.h`, ubicado en la ruta `/include/linux/`.
   En este archivo, se encuentra la línea correspondiente al nombre del sistema definido como `UTS_SYSNAME`.

   La modificación consiste en cambiar el valor de esta línea por el nombre personalizado deseado. Por ejemplo:

    ```c
    #define UTS_SYSNAME "CustomKernel"
    ```

   Después de realizar esta modificación, se debe recompilar el kernel. Una vez compilado e instalado, la
   personalización se puede verificar utilizando los comandos:

    ```bash
    uname -a
    uname -r
    ```

2. **Adición de un Mensaje de Bienvenida**
   Para agregar un mensaje de bienvenida al kernel, se debe modificar el archivo `main.c`, ubicado en la ruta `/init/`.
   En este archivo, buscar la función `start_kernel`, que se encarga de las inicializaciones al iniciar el kernel.

   Dentro de la función `start_kernel`, localizar la línea que contiene:

    ```c
    pr_notice("%s", linux_banner);
    ```

   Debajo de esta línea, agregar el siguiente código para incluir el mensaje de bienvenida:

    ```c
    printk(KERN_INFO "¡Bienvenido al kernel USAC! 😎\n");
    ```

   Después de realizar esta modificación, se debe recompilar el kernel. El mensaje agregado será visible durante el
   arranque del sistema o al consultar el registro de mensajes con el comando:

    ```bash
    dmesg | grep "¡Bienvenido al kernel USAC"
    ```
