#include "CapturePlatform.h"
#include <membership.h>

int rvi_uid_to_uuid(uid_t uid, uuid_t identity) {
    return mbr_uid_to_uuid(uid, identity);
}
