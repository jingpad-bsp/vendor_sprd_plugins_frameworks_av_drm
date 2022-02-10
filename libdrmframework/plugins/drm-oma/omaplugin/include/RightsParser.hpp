#ifndef __RIGHTS_PARSER_H__
#define __RIGHTS_PARSER_H__
#include <utils/String8.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <drm/drm_framework_common.h>
#include <common.hpp>
#include <drm/DrmRights.h>
#include <drm/DrmConstraints.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wundefined-bool-conversion"
#include <tinyxml.h>
#pragma GCC diagnostic pop

#include <tinystr.h>

#ifdef __LP64__
typedef time_t time64_t;
#define mktime64(t) (mktime(t))
#else
#include <time64.h>
#endif

namespace android {
class RightsParser {
   public:
    enum { UNSET = -2, INFINITY = -1, EXPIRED = 0 };

    enum State { UNKNOWN, OK, ERROR, NOT_ACQUIRED };

    enum { COUNT, DATETIME_START, DATETIME_END, INTERVAL_START, INTERVAL };

    RightsParser(const DrmRights& buffer);
    RightsParser(State state) : data(NULL), length(0), state(state) {}
    virtual ~RightsParser();
    bool parse();
    int checkRightsStatusForAction(int);
    DrmConstraints* getConstraintsForAction(int);

   private:
    String8 mimeType;
    char* data;
    int length;
    bool parseXML();
    bool parseWBXML();
    int64_t parseRELInterval(const char*);
    time64_t parseRELDateTime(const char*);
    void DumpConstrains();

   public:
    State state;
    String8 version;
    String8 uid;
    String8 key;

    // actions:
    // DEFAULT = 0x00; PLAY = 0x01; RINGTONE = 0x02; TRANSFER = 0x03;
    // OUTPUT = 0x04;PREVIEW = 0x05;EXECUTE = 0x06;DISPLAY = 0x07

    // mapping from drmframework to REL, this mapping must comply
    // with constants defined in drm_framework_common.h

    // constrains:  COUNT, DATETIME_START, DATETIME_END, INTERVAL_START, INTERVAL
    int64_t constraints[ACTION_NUM][CONSTRAINT_NUM];
};
};
#endif /* __RIGHTS_PARSER_H__ */
