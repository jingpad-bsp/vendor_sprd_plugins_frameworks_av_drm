#define LOG_TAG "DRM_DcfParser"
#include <DcfParser.hpp>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <utils/Log.h>
#include <openssl/evp.h>

using namespace android;

const static String8 CONTENT_NAME_KEY(KEY_CONTENT_NAME);
const static String8 CONTENT_VENDOR_KEY(KEY_CONTENT_VENDOR);
const static String8 EXTENDED_DATA_KEY(KEY_EXTENDED_DATA);
const static String8 RIGHTS_ISSUER_KEY(KEY_RIGHTS_ISSUER);


DcfParser::DcfParser(const char * file)
{
    construct(file, -1);
}

DcfParser::DcfParser(int fd)
{
    construct(NULL, fd);
}


DcfParser::DcfParser(const char * file, int fd)
{
    construct(file, fd);    
}

void DcfParser::construct(const char * file, int fd) {
    dcfFileName = file;
    this->fd = fd;

    firstRead = true;
    eof = false;
    offset = 0;
    length = 0;
    mDefaultAct = -1;
    version = 0;
    status = RightsStatus::RIGHTS_INVALID;

    decryptContext =new EVP_CIPHER_CTX();
}


DcfParser::~DcfParser() {
    if (fd != -1) {
        ::close(fd);
    }
    if (decryptContext) {
        delete decryptContext;
    }
}

bool DcfParser::parse() {

    if (fd == -1) {
        fd = ::open(dcfFileName, O_RDONLY);
        if (fd == -1) {
            ALOGE("parse %s error, open failed: %s", dcfFileName, ::strerror(errno));
            return false;
        }
    }
    ALOGD("parse %s, fd: %d", dcfFileName, fd);

    int version = 0;
    if (::lseek(fd, 0, SEEK_SET) == -1) {
        ALOGE("parse %s error, fd: %d, rewind file failed: %s", dcfFileName, fd, ::strerror(errno));
        return false;
    }
    if (::read(fd, &version, 1) == -1) {
        ALOGE("parse %s error, fd: %d, read failed: %s", dcfFileName, fd, ::strerror(errno));
        return false;
    }
    ALOGD("parse %s, version: %d", dcfFileName, version);
    if (version != 1) {
        // only dcf v1 is supported
        ALOGE("parse error, only dcf v1 is supported, %d", version);
        return false;
    }

    this->version = version;

    int contentTypeLen = 0;
    if (-1 == ::read(fd,&contentTypeLen,1)) {
        ALOGE("parse %s error, read fail! %s", dcfFileName, strerror(errno));
        return false;
    } else {
        if (0 == contentTypeLen) {
            ALOGE("parse %s error, contentTypeLen illegal!, file pos: %ld", dcfFileName, ::lseek(fd, 0, SEEK_CUR));
            return false;
        } else if (contentTypeLen > PARSER_CONTENT_TYPE_MAX) {
            ALOGE("parse %s error, contentTypeLen(%d) is too long!", dcfFileName, contentTypeLen);
            return false;
        } else {
            ALOGD("parse %s, contentTypeLen: %d", dcfFileName, contentTypeLen);
        }
    }

    int contentUriLen = 0;
    ::read(fd,&contentUriLen,1);
    if (!contentUriLen) {
        ALOGE("parse %s error, no contentUri!", dcfFileName);
        return false;
    } else if (contentUriLen > PARSER_CONTENT_URI_MAX) {
        ALOGE("parse %s error, contentUriLen(%d) is too long!", dcfFileName, contentUriLen);
        return false;
    } else {
        ALOGD("parse %s, contentUriLen: %d", dcfFileName, contentUriLen);
    }

    char contentType[contentTypeLen+1];
    bzero(contentType, contentTypeLen+1);

    ::read(fd, contentType, contentTypeLen);
    strtok(contentType, ";");
    this->contentType = String8 (contentType);
    if (this->contentType.isEmpty()) {
        ALOGE("parse error: no content type");
        return false;
    }
    ALOGD("parse %s, contentType: %s", dcfFileName, this->contentType.string());

    if (strstr(this->contentType.string(), "video/") || strstr(this->contentType.string(), "audio/") ||
               !strcmp(this->contentType.string(), "application/ogg")) {
        mDefaultAct = Action::PLAY;
    } else if (strstr(this->contentType.string(), "image/")) {
        mDefaultAct = Action::DISPLAY;
    }
    ALOGD("parse %s, default action: %d", dcfFileName, mDefaultAct);

    char contentUri[contentUriLen+1];
    bzero(contentUri, contentUriLen+1);
    ::read(fd, contentUri, contentUriLen);
    if (contentUri[0] == '<' && contentUri[contentUriLen-1] == '>') {
        contentUri[contentUriLen-1] = 0;
        this->contentUri = String8 (&(contentUri[1]));
    } else if (strstr(contentUri, "cid:")) {
        this->contentUri = String8 (&(contentUri[4]));
    } else {
        ALOGE("parse error: wrong content uri format: %s", contentUri);
        return false;
    }
    ALOGD("parse %s, contentUri: %s", dcfFileName, this->contentUri.string());

    int headersLen = 0;
    char uintFragment=0;
        for (int i = 0; i < 5; i++) {
            ::read(fd,&uintFragment,1);
            headersLen = (headersLen << 7) + (uintFragment & 0x7f);
            if ((uintFragment & (1<<7)) == 0) {
                break;
            }
        }
    ALOGD("parse %s, headersLen: %d", dcfFileName, headersLen);

    int dataLen = 0;
    uintFragment=0;
    for (int i = 0; i < 5; i++) {
        ::read(fd,&uintFragment,1);
        dataLen = (dataLen << 7) + (uintFragment & 0x7f);
        if ((uintFragment & (1<<7)) == 0) {
            break;
        }
    }
    ALOGD("parse %s, dataLen: %d", dcfFileName, dataLen);

    // parse headers
    if (headersLen <= PARSER_HEADER_MAX) {
        char headers[headersLen];
        bzero (headers, headersLen);
        ::read(fd, headers, headersLen);
        if (! parseHeader(headers, headersLen)) {
            return false;
        }
    } else {
        char* headers = new char[headersLen];
        if (headers) {
            bzero (headers, headersLen);
            ::read(fd, headers, headersLen);
            if (! parseHeader(headers, headersLen)) {
                delete[] headers;
                return false;
            }
            delete[] headers;
        } else {
            return false;
        }
    }
    offset = (int)::lseek(fd, 0, SEEK_CUR);
    length = (int)::lseek(fd, 0, SEEK_END);
    ::lseek(fd, offset, SEEK_SET);
    ALOGD("parse: dataOffset: %d, dateLen: %d" , offset, dataLen);
    return true;
}

bool DcfParser::parseHeader(const char* headers, int size) {
    unsigned int parse_err_ctx = 0;
    ALOGD("parseHeader: %s", headers);
    int tokenStart = 0;
    String8 currentKey;
    String8 currentValue;
    bool gotKey = false;
    for (int i = 0; i < size; ++i) {
        if (headers[i] == ':') {
            if (gotKey) {
                continue;
            }
            gotKey = true;
            currentKey = String8(headers+tokenStart, i-tokenStart);
            ALOGD("parseHeader: got key: %s", currentKey.string());
            // skip the succeeding ' '
            i++;
            tokenStart = i+1;
        } else if (headers[i] == 0x0d && headers[i+1] == 0x0a) {
            gotKey = false;
            currentValue = String8(headers+tokenStart, i-tokenStart);
            ALOGD("parseHeader: got value: %s", currentValue.string());
            // skip the succeeding 0x0a
            i++;
            tokenStart = i+1;

            if (currentKey == String8(DCF_ENCRYTION_METHOD)) {
            parse_err_ctx = 0;
            encryptionMethod = currentValue;
                if (encryptionMethod != String8(DCF_DEFAULT_ENCRYPTION_METHOD) &&
                    encryptionMethod != "AES128CBC;padding=RFC2630") {

                    ALOGE("parseHeader: unsupported encryptionMethod: %s", currentValue.string());
                    return false;
                }
            } else if (currentKey == String8(DCF_RIGHTS_ISSUER)) {
                parse_err_ctx = 0;
                rightsIssuer = currentValue;
            } else if (currentKey == String8(DCF_CONTENT_NAME)) {
                parse_err_ctx = 0;
                contentName = currentValue;
            } else if (currentKey == String8(DCF_CONTENT_DESCRIPTION)) {
                parse_err_ctx = 0;
                contentDescription = currentValue;
            } else if (currentKey == String8(DCF_CONTENT_VENDOR)) {
                parse_err_ctx = 0;
                contentVendor = currentValue;
            } else {
                parse_err_ctx++;
                ALOGE("parseHeader: unknown key: %s, err count: %d",currentKey.string(), parse_err_ctx);
                if (PARSE_ERR_MAX == parse_err_ctx) {
                    ALOGE("parseHeader: It seems like the file is corruption, quit...");
                    return false;
                }
            }
        }
    }
    return true;
}

bool DcfParser::setKey(char* transKey) {
    ALOGD("setKey: %s",transKey);
    // key is encoded in base64
    int origKeyLength = 0;
    unsigned char* origKey = unBase64((unsigned char*)transKey, &origKeyLength);
    memcpy(key, origKey, origKeyLength);
    free(origKey);
    return true;
}

int DcfParser::readBlock(char* buffer, int firstBlock, int numBlocks) {
    ALOGD("readBlock firstBlock:%d, numBlocks: %d, from fd:%d", firstBlock, numBlocks, fd);
    ::lseek(fd, offset+(firstBlock-1)*16, SEEK_SET);
    char iv[16] = {0};
    ::read(fd, iv, 16);
    EVP_CIPHER_CTX_init(decryptContext);
    EVP_DecryptInit_ex(decryptContext, EVP_aes_128_cbc(), NULL, key, (unsigned char*)iv);

    char cipherText[16] = {0};
    char* plainText = new char[numBlocks*16*2];
    bzero(plainText, numBlocks*16*2);
    int plainTextLen = 0;
    for (int i=firstBlock; i<firstBlock+numBlocks; ++i) {
        int cLen = ::read(fd, cipherText, 16);
        if (cLen == -1) {
            ALOGE("read plain text error %s", strerror(errno));
        }
        int pLen = 0;
        EVP_DecryptUpdate(decryptContext, (unsigned char*)plainText+plainTextLen, &pLen, (unsigned char*)cipherText, cLen);
        plainTextLen += pLen;
        if (::lseek(fd, 0, SEEK_CUR) == length) {
            EVP_DecryptFinal_ex(decryptContext, (unsigned char*)plainText+plainTextLen, &pLen);
            ALOGD("readBlock final %d, %d", plainTextLen, pLen);
            plainTextLen += pLen;
            eof = true;
            break;
        }
    }
    memcpy(buffer, plainText, plainTextLen);
    ALOGD("readBlock returns %d", plainTextLen);
    EVP_CIPHER_CTX_cleanup(decryptContext);

    delete[] plainText;
    plainText = NULL;
    return plainTextLen;
}

ssize_t DcfParser::readAt(char* outBuffer, ssize_t numBytes, int offset) {
    ALOGD("readAt %d:%d", numBytes, offset);
    // first prefix IV block is skipped
    int firstBlock = (int) (offset/16)+1;
    int numBlocks = (int)(numBytes/16)+10;

    ALOGD("readAt: numBlocks %d", numBlocks);
    char* tmpBuffer = new char[numBlocks*16];
    bzero(tmpBuffer, numBlocks*16);
    int ret = readBlock(tmpBuffer, firstBlock, numBlocks);
    if (ret < offset%16)
    {
        delete[] tmpBuffer;
        tmpBuffer = NULL;
        return 0;
    }
    ret -= offset%16;
    ret = (ret>numBytes)?numBytes:ret;
    memcpy(outBuffer, tmpBuffer+offset%16, ret);
    ALOGD("readAt returns %d", ret);

    delete[] tmpBuffer;
    tmpBuffer = NULL;
    return ret;
}

DrmMetadata* DcfParser::getMetadata() {
    DrmMetadata* ret =new DrmMetadata();
    if (!contentName.isEmpty()) {
        //ret->put(new String8(KEY_CONTENT_NAME), contentName.string());
        ret->put(&CONTENT_NAME_KEY, contentName.string());
    }

    if (!contentVendor.isEmpty()) {
        //ret->put(new String8(KEY_CONTENT_VENDOR), contentVendor.string());
        ret->put(&CONTENT_VENDOR_KEY, contentVendor.string());
    }

//  if (contentUri == String8(FAKE_UID)) {
    if (contentUri.find(FL_PREFIX, 0) != -1) {
        ret->put(&EXTENDED_DATA_KEY, "fl");
    } else if (rightsIssuer.isEmpty() &&
               contentName.isEmpty() &&
               contentDescription.isEmpty() &&
               contentVendor.isEmpty()) {
        ret->put(&EXTENDED_DATA_KEY, "cd");
    } else {
        ret->put(&RIGHTS_ISSUER_KEY, rightsIssuer.string());
        ret->put(&EXTENDED_DATA_KEY, "sd");
    }
    return ret;
}
