#pragma once

#include "QSEETrustlet.h"

#include <array>

#define QSEE_KEYMASTER64_MASTER_KEY_SIZE 0x98

typedef std::array<char, QSEE_KEYMASTER64_MASTER_KEY_SIZE> MasterKey;

class QSEEKeymasterTrustlet : public QSEETrustlet {
   public:
    QSEEKeymasterTrustlet();

    MasterKey GetKey();
};
