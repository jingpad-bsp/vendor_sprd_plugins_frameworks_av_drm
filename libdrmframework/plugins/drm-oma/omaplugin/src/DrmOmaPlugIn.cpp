/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//#define LOG_NDEBUG 0
#define LOG_TAG "DRM_DrmOmaPlugIn"
#include <utils/Log.h>

#include <drm/DrmRights.h>
#include <drm/DrmConstraints.h>
#include <drm/DrmMetadata.h>
#include <drm/DrmInfo.h>
#include <drm/DrmInfoEvent.h>
#include <drm/DrmInfoStatus.h>
#include <drm/DrmConvertedStatus.h>
#include <drm/DrmInfoRequest.h>
#include <drm/DrmSupportInfo.h>
#include <DrmOmaPlugIn.hpp>
#include <RightsManager.hpp>
#include <DcfParser.hpp>
#include <DcfCreator.hpp>
#include <DmParser.hpp>
#include <UUID.hpp>
#include <private/android_filesystem_config.h>

using namespace android;

#define OMA_DRM_PLUGIN_VER "2.0"

const String8 DrmOmaPlugIn::supportedFileSuffix[] = {String8(".dm"), String8(".dcf"), String8(".dr"), String8(".drc")};

// This extern "C" is mandatory to be managed by TPlugInManager
extern "C" IDrmEngine* create() { return new DrmOmaPlugIn(); }

// This extern "C" is mandatory to be managed by TPlugInManager
extern "C" void destroy(IDrmEngine* pPlugIn) {
    delete pPlugIn;
    pPlugIn = NULL;
}

DrmOmaPlugIn::DrmOmaPlugIn() : DrmEngineBase() {
    ALOGD("oma drm plugin version: %s", OMA_DRM_PLUGIN_VER);
    ALOGD("oma drm plugin is created");
}

DrmOmaPlugIn::~DrmOmaPlugIn() {}

DrmMetadata* DrmOmaPlugIn::onGetMetadata(int uniqueId, const String8* path) {
    ALOGD("(%d)onGetMetadata From Path: %s", uniqueId, path->string());
    DcfParser parser(path->string());
    if (!parser.parse()) {
        return NULL;
    }
    return parser.getMetadata();
}

DrmConstraints* DrmOmaPlugIn::onGetConstraints(int uniqueId, const String8* path, int action) {
    ALOGD("(%d)onGetConstraints from path: %s, action: %d", uniqueId, path->string(), action);
    DcfParser parser(path->string());
    if (!parser.parse()) {
        return new DrmConstraints();
    }
    return rightsManager.getConstraints(parser.contentUri, action);
}

#ifdef USE_LEGACY
DrmInfoStatus* DrmOmaPlugIn::onProcessDrmInfo(int uniqueId, const DrmInfo* drmInfo) {
    ALOGD("(%d)onProcessDrmInfo - Enter", uniqueId);
    /* mem leak? */
    const DrmBuffer* emptyBuffer = new DrmBuffer();
    DrmInfoStatus* errorStatus = new DrmInfoStatus(DrmInfoStatus::STATUS_ERROR, DrmInfoRequest::TYPE_REGISTRATION_INFO,
                                                   emptyBuffer, drmInfo->getMimeType());

    if (drmInfo == NULL) {
        return errorStatus;
    }

    String8 drmFilePath = drmInfo->get(String8(KEY_REQUEST_FILE_IN));
    String8 outputFilePath = drmInfo->get(String8(KEY_REQUEST_FILE_OUT));

    //    String8 drmFilePath = redirectPath(drmInfo->get(String8(KEY_REQUEST_FILE_IN)));
    //    String8 outputFilePath = redirectPath(drmInfo->get(String8(KEY_REQUEST_FILE_OUT)));
    ALOGD("DrmOmaPlugIn::onProcessDrmInfo - parse %s", drmFilePath.string());

    if (drmFilePath.isEmpty() || outputFilePath.isEmpty() || outputFilePath.getPathExtension() != String8(".dcf")) {
        return errorStatus;
    }

    DmParser parser(drmFilePath);
    if (!parser.parse()) {
        return errorStatus;
    }
    // save rights
    char* key = NULL;
    if (parser.hasRights()) {
        DrmRights rights = parser.getDrmRights();
        RightsParser rightsParser(rights);
        if (!rightsParser.parse()) {
            return errorStatus;
        }
        /* CD type should generate an unique uid, we generate it */
        if (strcmp(parser.dataContentId, FAKE_UID)) {
            UUID uuid;
            parser.dataContentId = uuid.generate();
            rightsParser.uid = parser.dataContentId;
        }
        if (rightsManager.saveRights(rightsParser) != DRM_NO_ERROR) {
            return errorStatus;
        }
        key = (char*)rightsParser.key.string();
    } else {
        // no rights? FL
        key = (char*)rightsManager.getFakeKey().string();
    }
    // convert content
    DcfCreator creator((char*)(outputFilePath.string()), key, parser.dataContentType, parser.dataContentId);

    char buffer[1024] = {0};
    int i = 0;
    while ((i = parser.read(buffer, 1024)) > 0) {
        if (creator.write(buffer, i) == -1) {
            return errorStatus;
        }
    }
    if (!creator.save()) {
        return errorStatus;
    }

    chmod(outputFilePath.string(), 0760);
    if (chown(outputFilePath.string(), -1, AID_MEDIA_RW) < 0) {
        ALOGE("onProcessDrmInfo - fail to chown %s, %s", outputFilePath.string(), strerror(errno));
    }

    DrmInfoStatus* okStatus = new DrmInfoStatus(DrmInfoStatus::STATUS_OK, DrmInfoRequest::TYPE_REGISTRATION_INFO,
                                                emptyBuffer, drmInfo->getMimeType());
    ALOGD("DrmOmaPlugIn::onProcessDrmInfo - Exit");
    return okStatus;
}
#else
DrmInfoStatus* DrmOmaPlugIn::onProcessDrmInfo(int uniqueId, const DrmInfo* drmInfo) {
    ALOGD("(%d)onProcessDrmInfo - Enter", uniqueId);
    if (drmInfo == NULL) {
        ALOGE("onProcessDrmInfo - drminfo is null!");
        return new DrmInfoStatus(DrmInfoStatus::STATUS_ERROR, DrmInfoRequest::TYPE_REGISTRATION_INFO,
                                                   new DrmBuffer(), String8::empty());
    }

    const DrmBuffer* emptyBuffer = new DrmBuffer();
    DrmInfoStatus* errorStatus = new DrmInfoStatus(DrmInfoStatus::STATUS_ERROR, DrmInfoRequest::TYPE_REGISTRATION_INFO,
                                                   emptyBuffer, drmInfo->getMimeType());

    String8 drmFilePath = drmInfo->get(String8(KEY_REQUEST_FILE_IN));
    String8 outputFilePath = drmInfo->get(String8(KEY_REQUEST_FILE_OUT));
    //    String8 drmFilePath = redirectPath(drmInfo->get(String8(KEY_REQUEST_FILE_IN)));
    //    String8 outputFilePath = redirectPath(drmInfo->get(String8(KEY_REQUEST_FILE_OUT)));
    String8 convertID = drmInfo->get(String8(KEY_CONVERT_ID));

    ALOGD("onProcessDrmInfo - parse %s, convertID = %s", drmFilePath.string(), convertID.string());

    if (drmFilePath.isEmpty() || convertID.isEmpty()) {
        ALOGE("onProcessDrmInfo failed");
        return errorStatus;
    }

    DmParser* parser = new DmParser(drmFilePath);
    if (!parser->parse()) {
        ALOGE("onProcessDrmInfo - dmparser failed!");
        delete parser;
        return errorStatus;
    }
    // save rights
    String8 key;
    if (parser->hasRights()) {
        ALOGE("onProcessDrmInfo, has rights,  parse and save rights");
        DrmRights rights = parser->getDrmRights();
        RightsParser rightsParser(rights);
        if (!rightsParser.parse()) {
            ALOGE("onProcessDrmInfo - parse rights failed!");
            delete parser;
            return errorStatus;
        }
        /* CD type should generate an unique uid, we generate it */
        if (strcmp(parser->dataContentId, FAKE_UID)) {
            UUID uuid;
            parser->dataContentId = uuid.generate();
            rightsParser.uid = parser->dataContentId;
        }
        if (rightsManager.saveRights(rightsParser) != DRM_NO_ERROR) {
            ALOGE("onProcessDrmInfo - save rights failed!");
            delete parser;
            return errorStatus;
        }
        key = rightsParser.key;
    } else {
        // no rights? FL
        key = rightsManager.getFakeKey();
        free(parser->dataContentId);
        parser->dataContentId = strdup(rightsManager.getFakeUid().string());
    }
    // convert content
    DcfCreator* creator = new DcfCreator((char*)(outputFilePath.string()), (char*)key.string(), parser->dataContentType,
                                         parser->dataContentId);

    if (!creator->convertHeaders()) {
        delete parser;
        delete creator;
        ALOGE("onProcessDrmInfo - convertHeaders failed!");
        return errorStatus;
    }

    delete emptyBuffer;
    delete errorStatus;
    size_t buffSize = creator->headers.size();
    char* buff = new char[buffSize];
    memcpy(buff, creator->headers.string(), buffSize);
    const DrmBuffer* headBuffer = new DrmBuffer(buff, buffSize);
    DrmInfoStatus* okStatus = new DrmInfoStatus(DrmInfoStatus::STATUS_OK, DrmInfoRequest::TYPE_REGISTRATION_INFO,
                                                headBuffer, drmInfo->getMimeType());
    DrmConvertEntity* entity = new DrmConvertEntity(creator, parser);
    int id = atoi(convertID.string());
    mConvertSessionMap.addValue(id, entity);
    ALOGD("onProcessDrmInfo - Exit");
    return okStatus;
}
#endif

status_t DrmOmaPlugIn::onSetOnInfoListener(int uniqueId, const IDrmEngine::OnInfoListener* /*infoListener*/) {
    ALOGD("onSetOnInfoListener : %d", uniqueId);
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onInitialize(int uniqueId) {
    ALOGD("onInitialize : %d", uniqueId);
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onTerminate(int uniqueId) {
    ALOGD("onTerminate : %d", uniqueId);
    return DRM_NO_ERROR;
}

DrmSupportInfo* DrmOmaPlugIn::onGetSupportInfo(int uniqueId) {
    ALOGD("onGetSupportInfo : %d", uniqueId);
    DrmSupportInfo* drmSupportInfo = new DrmSupportInfo();
    // add mimetype's
    drmSupportInfo->addMimeType(String8(MIMETYPE_DM));     // .dm
    drmSupportInfo->addMimeType(String8(MIMETYPE_DCF));    // .dcf
    drmSupportInfo->addMimeType(String8(MIMETYPE_RO));     // .dr
    drmSupportInfo->addMimeType(String8(MIMETYPE_WB_RO));  // .drc
    // add file suffixes
    for (unsigned int i = 0; i < sizeof(supportedFileSuffix) / sizeof(String8); ++i) {
        drmSupportInfo->addFileSuffix(supportedFileSuffix[i]);
    }
    // Add plug-in description
    drmSupportInfo->setDescription(String8("omav1 plug-in"));
    return drmSupportInfo;
}

// rightsPath and contentPath are just not used
status_t DrmOmaPlugIn::onSaveRights(int uniqueId, const DrmRights& drmRights, const String8& /*rightsPath*/,
                                    const String8& /*contentPath*/) {
    ALOGD("(%d)onSaveRights : mimetype = %s", uniqueId, drmRights.getMimeType().string());

    RightsParser parser(drmRights);
    if (!parser.parse()) {
        ALOGE("onSaveRights failed becuase rights object parse error");
        return DRM_ERROR_CANNOT_HANDLE;
    }
    return rightsManager.saveRights(parser);
}

#ifdef USE_LEGACY
DrmInfo* DrmOmaPlugIn::onAcquireDrmInfo(int uniqueId, const DrmInfoRequest* drmInfoRequest) {
    ALOGD("(%d)onAcquireDrmInfo", uniqueId));
    DrmInfo* drmInfo = NULL;

    if (drmInfoRequest == NULL) {
        return NULL;
    }

    String8 drmFilePath = drmInfoRequest->get(String8(KEY_REQUEST_FILE_IN));
    String8 outputFilePath = drmInfoRequest->get(String8(KEY_REQUEST_FILE_OUT));
    //    String8 drmFilePath = redirectPath(drmInfoRequest->get(String8(KEY_REQUEST_FILE_IN)));
    //    String8 outputFilePath = redirectPath(drmInfoRequest->get(String8(KEY_REQUEST_FILE_OUT)));

    ALOGD("onAcquireDrmInfo 1: %s->%s", drmFilePath.string(), outputFilePath.string());
    if (drmFilePath.isEmpty() || outputFilePath.isEmpty() || outputFilePath.getPathExtension() != String8(".dcf")) {
        return NULL;
    }
    ALOGD("onAcquireDrmInfo 2");

    DrmInfo* ret =
        new DrmInfo(drmInfoRequest->getInfoType(), DrmBuffer(strdup("nil"), 3), drmInfoRequest->getMimeType());
    ret->put(String8(KEY_REQUEST_FILE_IN), drmFilePath);
    ret->put(String8(KEY_REQUEST_FILE_OUT), outputFilePath);

    return ret;
}
#else
DrmInfo* DrmOmaPlugIn::onAcquireDrmInfo(int uniqueId, const DrmInfoRequest* drmInfoRequest) {
    ALOGD("(%d)onAcquireDrmInfo", uniqueId);
    DrmInfo* drmInfo = NULL;

    if (drmInfoRequest == NULL) {
        return NULL;
    }

    String8 drmFilePath = drmInfoRequest->get(String8(KEY_REQUEST_FILE_IN));
    String8 outputFilePath = drmInfoRequest->get(String8(KEY_REQUEST_FILE_OUT));
    //    String8 drmFilePath = redirectPath(drmInfoRequest->get(String8(KEY_REQUEST_FILE_IN)));
    //    String8 outputFilePath = redirectPath(drmInfoRequest->get(String8(KEY_REQUEST_FILE_OUT)));
    String8 convertID = drmInfoRequest->get(String8(KEY_CONVERT_ID));

    ALOGD("onAcquireDrmInfo, %s->%s", drmFilePath.string(), outputFilePath.string());
    if (drmFilePath.isEmpty() || convertID.isEmpty()) {
        ALOGE("onAcquireDrmInfo, drmFilePath(%s) or convertID(%s) is null", drmFilePath.string(), convertID.string());
        return NULL;
    }

    DrmInfo* ret =
        new DrmInfo(drmInfoRequest->getInfoType(), DrmBuffer(strdup("nil"), 3), drmInfoRequest->getMimeType());
    ret->put(String8(KEY_REQUEST_FILE_IN), drmFilePath);
    ret->put(String8(KEY_REQUEST_FILE_OUT), outputFilePath);
    ret->put(String8(KEY_CONVERT_ID), convertID);

    return ret;
}
#endif

bool DrmOmaPlugIn::onCanHandle(int uniqueId, const String8& path) {
    ALOGD("(%d)canHandle: %s ", uniqueId, path.string());
    String8 extension = path.getPathExtension();
    extension.toLower();
    for (unsigned int i = 0; i < sizeof(supportedFileSuffix) / sizeof(String8); ++i) {
        if (supportedFileSuffix[i] == extension) {
            return true;
        }
    }
    return false;
}

String8 DrmOmaPlugIn::onGetOriginalMimeType(int uniqueId, const String8& path, int /*fd*/) {
    ALOGD("(%d)onGetOriginalMimeType, %s", uniqueId, path.string());

    if (path.getPathExtension() != ".dcf") {
        ALOGE("onGetOriginalMimeType %s failed: can only parse dcf filetype!", path.string());
        return String8(DCF_UNKNOWN_CONTENT_TYPE);
    }

    DcfParser parser = DcfParser(path.string());
    bool isDcf = parser.parse();
    String8 ret;
    if (isDcf) {
        ret = parser.contentType;
    } else {
        ALOGE("onGetOriginalMimeType, parse dcf file failed, %s", path.string());
        ret = String8(DCF_UNKNOWN_CONTENT_TYPE);
    }

    ALOGD("onGetOriginalMimeType for %s returns %s", path.string(), ret.string());
    return ret;
}

int DrmOmaPlugIn::onGetDrmObjectType(int uniqueId, const String8& path, const String8& mimeType) {
    ALOGD("(%d)onGetDrmObjectType : %s, mimeType: %s", uniqueId, path.string(), mimeType.string());
    if (mimeType == String8("application/vnd.oma.drm.message")) {
        return DrmObjectType::TRIGGER_OBJECT;
    }
    if (mimeType == String8("application/vnd.oma.drm.content")) {
        return DrmObjectType::CONTENT;
    }
    if (mimeType == String8("application/vnd.oma.drm.rights+xml") ||
        mimeType == String8("application/vnd.oma.drm.rights+wbxml")) {
        return DrmObjectType::RIGHTS_OBJECT;
    }

    String8 extension = path.getPathExtension();
    extension.toLower();

    if (extension == String8(".dcf")) {
        return DrmObjectType::CONTENT;
    }
    if (extension == String8(".dm")) {
        return DrmObjectType::TRIGGER_OBJECT;
    }
    if (extension == String8(".dr") || extension == String8(".drc")) {
        return DrmObjectType::RIGHTS_OBJECT;
    }

    return DrmObjectType::UNKNOWN;
}

int DrmOmaPlugIn::onCheckRightsStatus(int uniqueId, const String8& path, int action) {
    ALOGD("(%d)onCheckRightsStatus, path: %s, action: %d", uniqueId, path.string(), action);
    int ret = RightsStatus::RIGHTS_INVALID;

    DcfParser parser(path);
    if (!parser.parse()) {
        return RightsStatus::RIGHTS_INVALID;
    }
    // special case for SD & TRANSFER
    if (action == Action::TRANSFER &&
        // parser.contentUri != String8(FAKE_UID) &&
        parser.contentUri.find(FL_PREFIX, 0) == -1 && !parser.rightsIssuer.isEmpty()) {
        ALOGD("onCheckRightsStatus, sd file always has transfer right");
        return RightsStatus::RIGHTS_VALID;
    }
    if (Action::DEFAULT == action) {
        ret = rightsManager.checkRightsStatus(parser.contentUri, parser.mDefaultAct);
    } else {
        ret = rightsManager.checkRightsStatus(parser.contentUri, action);
    }

    ALOGD("onCheckRightsStatus, path: %s, action: %d, ret: %d", path.string(), action, ret);
    return ret;
}

status_t DrmOmaPlugIn::onConsumeRights(int uniqueId, sp<DecryptHandle>& /*decryptHandle*/, int /*action*/, bool /*reserve*/) {
    SUNWAY_NOISY(ALOGD("onConsumeRights : %d", uniqueId));
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onSetPlaybackStatus(int uniqueId, sp<DecryptHandle>& decryptHandle, int playbackStatus,
                                           int64_t /*position*/) {
    ALOGD("(%d)onSetPlaybackStatus, status: %d", uniqueId, playbackStatus);
    DcfParser* parser = decodeSessionMap.getValue(decryptHandle->decryptId);
    RightsConsumer* consumer = consumeSessionMap.getValue(decryptHandle->decryptId);
    bool eof = false;
    if (playbackStatus == 0) {
		parser->status = rightsManager.checkRightsStatus(parser->contentUri, parser->mDefaultAct);
    }
    ALOGD("(%d)onSetPlaybackStatus, contentType: %s", uniqueId, parser->contentType.string());
    if ((playbackStatus == 4) || ((playbackStatus == 1) && (strstr(parser->contentType.string(), "image/")))) {
        eof = true;
	playbackStatus = 1;
    }
    if (consumer) {
        consumer->setPlaybackStatus(playbackStatus, eof);
        if (consumer->shouldConsume()) {
            RightsParser rightsParser = rightsManager.query(parser->contentUri);
            ALOGD("before parse: version: %s", rightsParser.version.string());
            if (rightsParser.parse()) {
                ALOGD("before consume: version: %s", rightsParser.version.string());
                if (consumer->consume(rightsParser)) {
                    ALOGD("after consume: version: %s", rightsParser.version.string());
                    rightsManager.saveRights(rightsParser);
                    parser->clear();
                }
            }
        }
        if ((playbackStatus == 0) && consumer->shouldIndicateConsume()) {
	    RightsParser rightsParser = rightsManager.query(parser->contentUri);
            ALOGD("before parse: version: %s!", rightsParser.version.string());
            if (rightsParser.parse()) {
                ALOGD("before indicateConsume: version: %s", rightsParser.version.string());
                if (consumer->indicateConsume(rightsParser)) {
                    ALOGD("after indicateConsume: version: %s", rightsParser.version.string());
                    rightsManager.saveRights(rightsParser);
                    parser->clear();
                }
            }
		}
    }
    return DRM_NO_ERROR;
}

bool DrmOmaPlugIn::onValidateAction(int uniqueId, const String8& /*path*/, int /*action*/,
                                    const ActionDescription& /*description*/) {
    SUNWAY_NOISY(ALOGD("onValidateAction() : %d", uniqueId));
    return true;
}

status_t DrmOmaPlugIn::onRemoveRights(int uniqueId, const String8& /*path*/) {
    SUNWAY_NOISY(ALOGD("onRemoveRights() : %d", uniqueId));
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onRemoveAllRights(int uniqueId) {
    SUNWAY_NOISY(ALOGD("onRemoveAllRights() : %d", uniqueId));
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onOpenConvertSession(int uniqueId, int /*convertId*/) {
    SUNWAY_NOISY(ALOGD("onOpenConvertSession() : %d", uniqueId));
    return DRM_NO_ERROR;
}

DrmConvertedStatus* DrmOmaPlugIn::onConvertData(int uniqueId, int convertId, const DrmBuffer* /*inputData*/) {
    ALOGD("(%d)onConvertData , convertId = %d", uniqueId, convertId);
    DrmConvertEntity* entity = mConvertSessionMap.getValue(convertId);

    if (!entity) return new DrmConvertedStatus(DrmConvertedStatus::STATUS_ERROR, 0, 0);
    char inbuff[CONVERT_SIZE];
    bzero(inbuff, CONVERT_SIZE);
    ssize_t bytesReaded = entity->mParser->read(inbuff, CONVERT_SIZE);
    if (bytesReaded > 0) {
        ssize_t bytesToWrite = 0;
        char* tmp = entity->mCreater->convert(inbuff, bytesReaded, &bytesToWrite);
        if (tmp && bytesToWrite) {
            ALOGD("onConvertData, bytes converted = %d", bytesToWrite);
            char* outbuff = new char[bytesToWrite];
            memcpy(outbuff, tmp, bytesToWrite);
            delete[] tmp;
            DrmBuffer* convertedData = new DrmBuffer(outbuff, bytesToWrite);
            return new DrmConvertedStatus(DrmConvertedStatus::STATUS_OK, convertedData, 0);
        } else {
            ALOGE("onConvertData, convert error!");
            return new DrmConvertedStatus(DrmConvertedStatus::STATUS_ERROR, 0, 0);
        }

    } else if (bytesReaded == 0) {
        ALOGD("onConvertData, bytes converted final");
        return new DrmConvertedStatus(DrmConvertedStatus::STATUS_OK, 0, 0);

    } else {
        ALOGE("onConvertData, convert error!");
        return new DrmConvertedStatus(DrmConvertedStatus::STATUS_ERROR, 0, 0);
    }
}

DrmConvertedStatus* DrmOmaPlugIn::onCloseConvertSession(int uniqueId, int convertId) {
    ALOGD("(%d)onCloseConvertSession , convertId = %d", uniqueId, convertId);
    DrmConvertEntity* entity = mConvertSessionMap.getValue(convertId);

    if (!entity) return new DrmConvertedStatus(DrmConvertedStatus::STATUS_ERROR, 0, 0);

    char buff[1024];
    bzero(buff, 1024);
    int bytesToWrite = entity->mCreater->convertend(buff);
    ALOGD("onCloseConvertSession , padding size = %d", bytesToWrite);
    mConvertSessionMap.removeValue(convertId);
    if (bytesToWrite) {
        char* outbuff = new char[bytesToWrite];
        memcpy(outbuff, buff, bytesToWrite);
        DrmBuffer* convertedData = new DrmBuffer(outbuff, bytesToWrite);
        return new DrmConvertedStatus(DrmConvertedStatus::STATUS_OK, convertedData, 0);
    } else {
        return new DrmConvertedStatus(DrmConvertedStatus::STATUS_OK, 0, 0);
    }
}

status_t DrmOmaPlugIn::onOpenDecryptSession(int uniqueId, sp<DecryptHandle>& decryptHandle, int fd, off64_t offset,
                                            off64_t length) {
    ALOGD("(%d)onOpenDecryptSession : offset:%d, length:%d, fd:%d", uniqueId, (int)offset, (int)length, fd);
    DcfParser* parser = new DcfParser(dup(fd));
    if (!parser->parse()) {
        ALOGE("onOpenDecryptSession , dcf parse error");
        delete parser;
        return DRM_ERROR_CANNOT_HANDLE;
    }
    RightsParser rightsParser = rightsManager.query(parser->contentUri);
    if (!rightsParser.parse()) {
        ALOGE("onOpenDecryptSession, rights parse error");
        delete parser;
        return DRM_ERROR_CANNOT_HANDLE;
    }
    int status = rightsManager.checkRightsStatus(parser->contentUri, parser->mDefaultAct);
    ALOGD("default Action %d, status %d\n", parser->mDefaultAct, status);
    if (status != RightsStatus::RIGHTS_VALID) {
        ALOGE("onOpenDecryptSession, default action rights invalid\n");
        delete parser;
        return DRM_ERROR_CANNOT_HANDLE;
    }
    ALOGD("set key: %s", rightsParser.key.string());
    parser->setKey((char*)rightsParser.key.string());
    parser->status = status;
    decodeSessionMap.addValue(decryptHandle->decryptId, parser);
    consumeSessionMap.addValue(decryptHandle->decryptId, new RightsConsumer());

    decryptHandle->mimeType = parser->contentType;
    decryptHandle->decryptApiType = DecryptApiType::CONTAINER_BASED;
    decryptHandle->status = status;
    // decryptHandle->status = DRM_NO_ERROR;
    decryptHandle->decryptInfo = NULL;
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onOpenDecryptSession(int uniqueId, sp<DecryptHandle>& /*decryptHandle*/, const char* /*uri*/) {
    ALOGD("(%d)onOpenDecryptSession", uniqueId);
    return DRM_ERROR_CANNOT_HANDLE;
}

status_t DrmOmaPlugIn::onCloseDecryptSession(int uniqueId, sp<DecryptHandle>& decryptHandle) {
    ALOGD("(%d)onCloseDecryptSession", uniqueId);
    if (NULL != decryptHandle.get()) {
        decodeSessionMap.removeValue(decryptHandle->decryptId);
        consumeSessionMap.removeValue(decryptHandle->decryptId);
        if (NULL != decryptHandle->decryptInfo) {
            delete decryptHandle->decryptInfo;
            decryptHandle->decryptInfo = NULL;
        }
        /*delete decryptHandle;
        decryptHandle = NULL; */
    }
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onInitializeDecryptUnit(int uniqueId, sp<DecryptHandle>& /*decryptHandle*/, int /*decryptUnitId*/,
                                               const DrmBuffer* /*headerInfo*/) {
    ALOGD("(%d)onInitializeDecryptUnit", uniqueId);
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onDecrypt(int uniqueId, sp<DecryptHandle>& /*decryptHandle*/, int /*decryptUnitId*/,
                                 const DrmBuffer* encBuffer, DrmBuffer** decBuffer, DrmBuffer* /*IV*/) {
    ALOGD("(%d)onDecrypt", uniqueId);
    /**
     * As a workaround implementation oma would copy the given
     * encrypted buffer as it is to decrypted buffer. Note, decBuffer
     * memory has to be allocated by the caller.
     */
    if (NULL != (*decBuffer) && 0 < (*decBuffer)->length) {
        if ((*decBuffer)->length >= encBuffer->length) {
            memcpy((*decBuffer)->data, encBuffer->data, encBuffer->length);
            (*decBuffer)->length = encBuffer->length;
        } else {
            ALOGE("decBuffer size (%d) too small to hold %d bytes", (*decBuffer)->length, encBuffer->length);
            return DRM_ERROR_UNKNOWN;
        }
    }
    return DRM_NO_ERROR;
}

status_t DrmOmaPlugIn::onFinalizeDecryptUnit(int uniqueId, sp<DecryptHandle>& /*decryptHandle*/, int /*decryptUnitId*/) {
    ALOGD("(%d)onFinalizeDecryptUnit", uniqueId);
    return DRM_NO_ERROR;
}

#define GET_SIZE_MAGIC 0xDEADBEEF
#define PADDING_SNIFF_SIZE 512
/*
 * In this func, we have a secreat code which is the "DEADBEEF".
 * If the incoming offset equals to the magic num, the pread will do NOT read anything,
 * but return the plain text length quickly.
 * This is a workaround as the google drm framework lack of a getSize like func.
 */
ssize_t DrmOmaPlugIn::onPread(int uniqueId, sp<DecryptHandle>& decryptHandle, void* buffer, ssize_t numBytes,
                              off64_t offset) {
    ALOGD("(%d)onPread, numBytes: %d, offset: %d", uniqueId, (int)numBytes, (int)offset);
    DcfParser* parser = decodeSessionMap.getValue(decryptHandle->decryptId);

    if (parser) {
        if (GET_SIZE_MAGIC == offset && parser->fd != -1) {
            off64_t rawsize = 0;
            offset = 0;
            struct stat64 stat_buf;
            if (::fstat64(parser->fd, &stat_buf) != -1) {
                rawsize = stat_buf.st_size;
                if (rawsize > PADDING_SNIFF_SIZE) {
                    char buf[1024] = {0};
                    /*
                     * read the cipher text from the last padding sniff area, so that we can get
                     * the real plain text length more quickly
                     */
                    int paddingSize = parser->readAt(buf, 1024, rawsize - PADDING_SNIFF_SIZE);
                    offset = rawsize - PADDING_SNIFF_SIZE + paddingSize;
                } else {
                    offset = rawsize;
                }
            }

            ALOGD("onPread, for getSize only! rawsize = %lld, realsize = %lld", rawsize, offset);
            return offset;
        } else if (parser->status == RightsStatus::RIGHTS_VALID) {
                   return parser->readAt((char*)buffer, numBytes, (int)offset);
               } else {
		   ALOGE("onPread error, RightsStatus %d", parser->status);
		   return -1;
	       }
    } else {
        ALOGE("onPread error, no parser");
        return -1;
    }
}
