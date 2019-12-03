#pragma once

#include <linux/uinput.h>

__BEGIN_DECLS

typedef struct {
    int fd;
} fpc_uinput_t;

int fpc_uinput_create(fpc_uinput_t *);
int fpc_uinput_destroy(fpc_uinput_t *);
int fpc_uinput_send(const fpc_uinput_t *, unsigned short keycode, unsigned short value);
int fpc_uinput_click(const fpc_uinput_t *uinput, unsigned short keycode);

__END_DECLS

#ifdef __cplusplus

class UInput {
    fpc_uinput_t uinput;

   public:
    UInput();
    ~UInput();

    void Click(unsigned short keycode);
};

#endif
