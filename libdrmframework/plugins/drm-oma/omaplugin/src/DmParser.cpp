#define LOG_TAG "DRM_DmParser"
#include <DmParser.hpp>
#include <stdio.h>
#include <utils/Log.h>
#include <strings.h>

using namespace android;

DmParser::DmParser(const char* file)
    : dmFileName(file),
      rightsContentType(NULL),
      rightsStartOffset(0),
      rightsEndOffset(0),
      dataStartOffset(0),
      dataEndOffset(0),
      rightsData(NULL),
      firstRead(true),
      boundary(0),
      dataContentType(NULL),
      dataTransferEncoding(UNKNOWN),
      dataContentId(NULL) {
    this->file = fopen(dmFileName, "r");
    if (!this->file) {
        SUNWAY_NOISY(ALOGE("DmParser::open file %s  error %s", dmFileName, strerror(errno)));
    }
}

DmParser::~DmParser() {
    if (file) {
        fclose(file);
    }
    if (rightsContentType) {
        free(rightsContentType);
    }
    if (dataContentType) {
        free(dataContentType);
    }
    if (dataContentId) {
        free(dataContentId);
    }
    if (rightsData) {
        free(rightsData);
        rightsData = NULL;
    }
    if (boundary) delete[] boundary;
}

bool DmParser::parseOneBoundary() {
    char buffer[MAX_LINE] = {0};
    char contentType[MAX_LINE] = {0};
    char contentTransferEncoding[MAX_LINE] = {0};
    char contentId[MAX_LINE] = {0};

    char* line = NULL;
    while ((line = fgets(buffer, MAX_LINE, file)) && (strlen(chomp(line)))) {
        char* colon = strchr(line, ':');
        if (colon) {
            *colon = 0x0;
            char* key = line;
            char* value = colon + 2;  // skip the space after colon
            if (strcmp(key, HTTP_CONTENT_TYPE) == 0 || strcmp(key, HTTP_CONTENT_TYPE1) == 0) {
                memcpy(contentType, value, strlen(value));
            } else if (strcmp(key, HTTP_CONTENT_TRANSFER_ENCODING) == 0) {
                memcpy(contentTransferEncoding, value, strlen(value));
            } else if (strcmp(key, HTTP_CONTENT_ID) == 0) {
                value[strlen(value) - 1] = 0;
                value++;
                memcpy(contentId, value, strlen(value));
            } else {
                SUNWAY_NOISY(ALOGE("DmParser::parse %s:unknown key:value %s: %s", dmFileName, key, value));
            }
        }
    }

    if (!strcmp(contentType, MIMETYPE_RO) || !strcmp(contentType, MIMETYPE_WB_RO)) {
        // save rights
        rightsContentType = strdup(contentType);
        rightsStartOffset = ftell(file);
        rightsEndOffset = seekToNextBoundary();
        return rightsEndOffset != -1;
    } else if (strlen(contentType) != 0) {
        // set content type
        dataContentType = strdup(contentType);
        // set transfer encoding
        if (strlen(contentTransferEncoding) == 0 || !strcmp(contentTransferEncoding, "binary")
            || !strcmp(contentTransferEncoding, "7bit") || !strcmp(contentTransferEncoding, "8bit")) {
            dataTransferEncoding = BINARY;
        } else if (!strcmp(contentTransferEncoding, "base64")) {
            dataTransferEncoding = BASE64;
        } else {
            // only binary and base64 transfer encoding is supported;
            dataTransferEncoding = UNKNOWN;
            return false;
        }
        // set content id
        if (hasRights() && strlen(contentId) == 0) {
            return false;
        }

        if (strlen(contentId) == 0) {
            // this is FL, set fake contentId
            dataContentId = strdup(FAKE_UID);
        } else {
            dataContentId = strdup(contentId);
        }

        dataStartOffset = ftell(file);
        dataEndOffset = seekToNextBoundary();
        return false;
    } else {
        SUNWAY_NOISY(ALOGE("DmParser::parse %s: no content type", dmFileName));
        fclose(file);
        return false;
    }
}

int DmParser::seekToNextBoundary() {
    char buffer[MAX_LINE] = {0};
    char* line = NULL;
    if (!boundary) {
        SUNWAY_NOISY(ALOGE("DmParser::seekToNextBoundary: no boundary delimiter!"));
        return -1;
    }
    int ret = ftell(file);
    while ((line = fgets(buffer, MAX_LINE, file)) && (!strstr(chomp(line), boundary))) {
        ret = ftell(file);
    }
    if (!line) {
        SUNWAY_NOISY(ALOGE("DmParser::seekToNextBoundary: can't find boundary!"));
        return -1;
    }
    if (-1 == ret) {
        SUNWAY_NOISY(ALOGE("DmParser::seekToNextBoundary: %s", strerror(errno)));
    }
    return ret;
}

bool DmParser::parse() {
    if (!file) {
        return false;
    }
    SUNWAY_NOISY(ALOGD("DmParser::parse %s", dmFileName));
    rewind(file);
    if (!file) {
        SUNWAY_NOISY(ALOGE("DmParser::parse %s, open failed: %s", dmFileName, ::strerror(errno)));
        return false;
    }
    seekBoundaryDelimiter();
    while (parseOneBoundary()) {
    }
    if (dataStartOffset != 0 && dataEndOffset != 0) {
        SUNWAY_NOISY(
            ALOGD("DmParser::parse %s, ok, parse result: rights: from %d to %d; data: from %d to %d, contentType: %s, "
                  "contentId: %s, encoding: %d",
                  dmFileName, rightsStartOffset, rightsEndOffset, dataStartOffset, dataEndOffset, dataContentType,
                  dataContentId, dataTransferEncoding));
        return true;
    }
    return false;
}

DrmRights DmParser::getDrmRights() {
    char* buffer = NULL;
    if (rightsData) {
        buffer = rightsData;
    } else {
        buffer = (char*)malloc(rightsEndOffset - rightsStartOffset);
        int fsk = fseek(file, rightsStartOffset, SEEK_SET);
        if (fsk == -1) abort();
        int frd = fread(buffer, 1, rightsEndOffset - rightsStartOffset, file);
        if (frd != (rightsEndOffset - rightsStartOffset)) abort();
        rightsData = buffer;
    }
    DrmRights ret(DrmBuffer(buffer, rightsEndOffset - rightsStartOffset), String8(rightsContentType));
    return ret;
}

// Note: EOF only when DmParser::read returns 0
int DmParser::read(char* outBuffer, int numBytes) {
    if (firstRead == true) {
        firstRead = false;
        int fsk = fseek(file, dataStartOffset, SEEK_SET);
        if (fsk == -1) return 0;
        if (dataTransferEncoding == BASE64) {
            EVP_DecodeInit(&decodeContext);
        }
    }

    char buffer[numBytes];
    bzero(buffer, numBytes);

    int size = 0;
    if (ftell(file) + numBytes >= dataEndOffset) {
        size = fread(buffer, 1, dataEndOffset - ftell(file) - 2, file);
    } else {
        size = fread(buffer, 1, numBytes, file);
    }

    if (size == 0) {
        return 0;
    }
    if (dataTransferEncoding == BASE64) {
        char plainText[size];
        bzero(plainText, size);
        int plainTextLength = 0;
        EVP_DecodeUpdate(&decodeContext, (unsigned char*)plainText, &plainTextLength, (unsigned char*)buffer, size);
        memcpy(outBuffer, plainText, plainTextLength);
        if (size != numBytes) {
            // end of file
            int finalLength = 0;
            EVP_DecodeFinal(&decodeContext, (unsigned char*)&plainText[plainTextLength], &finalLength);
            plainTextLength += finalLength;
        }
        return plainTextLength;
    } else {
        memcpy(outBuffer, buffer, size);
        return size;
    }
}

void DmParser::seekBoundaryDelimiter() {
    if (!file) return;
    rewind(file);
    char buffer[MAX_LINE] = {0};
    char* line = NULL;
    while ((line = fgets(buffer, MAX_LINE, file)) && (!strlen(chomp(line)))) {
    }
    if (!line) return;
    ALOGD("DmParser::seekBoundaryDelimiter: line = %s, len = %d", line, strlen(line));
    for (unsigned int i = 0; i < strlen(line); i++) {
        if (' ' == line[i] || '\t' == line[i]) {
            continue;
        } else if ('-' == line[i] && '-' == line[i + 1]) {
            int len = strlen(line + i);
            if (boundary) delete[] boundary;
            boundary = new char[len + 1];
            memcpy(boundary, line + i, len + 1);
            SUNWAY_NOISY(ALOGD("DmParser::seekBoundaryDelimiter: boundary = %s", boundary));
            break;
        } else {
            break;
        }
    }
}
