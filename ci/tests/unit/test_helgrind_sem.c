/* Helgrind suppression controls: valid IPC, an unrelated wait and a race. */
#include <pthread.h>
#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

static int race_mode;
static volatile int raced;

__attribute__((noinline)) void *
ngx_shmtx_lock(void *arg)
{
    if (race_mode) {
        raced++;
    } else if (sem_wait(arg) != 0) {
        perror("sem_wait");
        exit(2);
    }
    return NULL;
}

__attribute__((noinline)) static void
other_sem_wait(sem_t *sem)
{
    if (sem_wait(sem) != 0) {
        perror("sem_wait");
        exit(2);
    }
}

int
main(int argc, char **argv)
{
    if (argc != 2) {
        return 64;
    }
    if (strcmp(argv[1], "race") == 0) {
        pthread_t first, second;
        race_mode = 1;
        if (pthread_create(&first, NULL, ngx_shmtx_lock, NULL) != 0
            || pthread_create(&second, NULL, ngx_shmtx_lock, NULL) != 0)
        {
            return 2;
        }
        if (pthread_join(first, NULL) != 0 || pthread_join(second, NULL) != 0) {
            return 2;
        }
        return 0;
    }
    if (strcmp(argv[1], "ipc") != 0 && strcmp(argv[1], "outside") != 0) {
        return 64;
    }

    sem_t *sem = mmap(NULL, sizeof(*sem), PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (sem == MAP_FAILED || sem_init(sem, 1, 0) != 0) {
        return 2;
    }
    pid_t child = fork();
    if (child < 0) {
        return 2;
    }
    if (child == 0) {
        if (strcmp(argv[1], "outside") == 0) {
            other_sem_wait(sem);
        } else {
            ngx_shmtx_lock(sem);
        }
        return 0;
    }
    if (sem_post(sem) != 0) {
        return 2;
    }
    int status;
    if (waitpid(child, &status, 0) < 0) {
        return 2;
    }
    sem_destroy(sem);
    munmap(sem, sizeof(*sem));
    return WIFEXITED(status) ? WEXITSTATUS(status) : 2;
}
