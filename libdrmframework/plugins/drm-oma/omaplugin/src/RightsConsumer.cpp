#define LOG_TAG "DRM_RightsConsumer"
#include <RightsConsumer.hpp>


using namespace android;

RightsConsumer::RightsConsumer()
    :startTime(TIME_INVALID), intervalStartTime(TIME_INVALID), isEof(false), endTime(TIME_INVALID), interval(0), needConsume(false),
    startConsume(true)
{

}

RightsConsumer::~RightsConsumer() {

}

void RightsConsumer::setPlaybackStatus(int status, bool eof) {
    ALOGD("RightsConsumer::setPlaybackStatus() : %d, %d", status, eof);
    time64_t currentTime = getCurrentTime();
    SUNWAY_NOISY (ALOGD("RightsConsumer::setPlaybackStatus:currentTime: %lld", currentTime));
    if (currentTime == TIME_INVALID) {
        SUNWAY_NOISY (ALOGE("RightsConsumer::setPlaybackStatus(), but currentTime is invalid"));
        needConsume = false;
        return;
    }
    isEof = eof;
    if (status == Playback::START) {
        SUNWAY_NOISY (ALOGD("RightsConsumer::setPlaybackStatus():START"));
        startTime = currentTime;
        intervalStartTime = startTime;
    } else if (status == Playback::PAUSE){
        if (startTime != TIME_INVALID) {
            interval += (currentTime-startTime);
            startTime = TIME_INVALID;
            SUNWAY_NOISY (ALOGD("RightsConsumer::setPlaybackStatus():PAUSE: update interval to %lld", interval));
        }
        if (eof && (interval != 0)) {
            needConsume = true;
        }
    } else if (status == Playback::STOP) {
        if (startTime != TIME_INVALID) {
            interval += (currentTime-startTime);
            startTime = TIME_INVALID;
            SUNWAY_NOISY (ALOGD("RightsConsumer::setPlaybackStatus():STOP: update interval to %lld", interval));
        }
        if (interval != 0) {
            needConsume = true;
        }
    }
}

void RightsConsumer::consumeForAction(RightsParser& rightsParser, int action) {
    int64_t* constraintsForAction = rightsParser.constraints[action];
    if (constraintsForAction[RightsParser::COUNT] != RightsParser::UNSET &&
        constraintsForAction[RightsParser::COUNT] != RightsParser::INFINITY &&
        constraintsForAction[RightsParser::COUNT] != RightsParser::EXPIRED && isEof) {
        constraintsForAction[RightsParser::COUNT] --;
        if (constraintsForAction[RightsParser::COUNT] < 0) {
            constraintsForAction[RightsParser::COUNT] = RightsParser::EXPIRED;
        }
    }

    if (constraintsForAction[RightsParser::INTERVAL] != RightsParser::UNSET &&
        constraintsForAction[RightsParser::INTERVAL_START] == RightsParser::UNSET &&
        intervalStartTime != TIME_INVALID) {
        SUNWAY_NOISY (ALOGD("RightsConsumer::consumeForAction: action is %d, interval_start is %lld", action, intervalStartTime));
        constraintsForAction[RightsParser::INTERVAL_START] = intervalStartTime;
    }
}

bool RightsConsumer::consume(RightsParser& rightsParser) {
    SUNWAY_NOISY (ALOGD("RightsConsumer::consume: interval is %lld", interval));
    if (needConsume) {
        needConsume = false;
        int actions[] = {Action::PLAY, Action::DISPLAY};
        for (unsigned int i = 0; i < sizeof(actions)/sizeof(actions[0]); ++i) {
            consumeForAction(rightsParser, actions[i]);
        }
        interval = 0;
        isEof = false;
        return true;
    }
    return false;
}

bool RightsConsumer::shouldConsume() {
    return needConsume;
}

void RightsConsumer::startConsumeForAction(RightsParser& rightsParser, int action) {
    int64_t* constraintsForAction = rightsParser.constraints[action];
    if (constraintsForAction[RightsParser::INTERVAL] != RightsParser::UNSET &&
        constraintsForAction[RightsParser::INTERVAL_START] == RightsParser::UNSET &&
        intervalStartTime != TIME_INVALID) {
        SUNWAY_NOISY (ALOGD("RightsConsumer::startConsumeForAction: action is %d, interval_start is %lld", action, intervalStartTime));
        constraintsForAction[RightsParser::INTERVAL_START] = intervalStartTime;
    }
}

bool RightsConsumer::indicateConsume(RightsParser& rightsParser) {
    SUNWAY_NOISY (ALOGD("RightsConsumer::indicateConsume: interval is %lld", interval));
    if (startConsume) {
        startConsume = false;
        int actions[] = {Action::PLAY, Action::DISPLAY};
        for (unsigned int i = 0; i < sizeof(actions)/sizeof(actions[0]); ++i) {
            startConsumeForAction(rightsParser, actions[i]);
        }
        return true;
    }
    return false;
}

bool RightsConsumer::shouldIndicateConsume() {
    return startConsume;
}
