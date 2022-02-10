#ifndef RIGHTS_CONSUMER_HPP
#define RIGHTS_CONSUMER_HPP
#include <RightsParser.hpp>
#include <common.hpp>

namespace android {
    class RightsConsumer {

    private:
        bool     isEof;
        time64_t startTime;
        time64_t intervalStartTime;
        time64_t endTime;
        time64_t interval;
        bool needConsume;
        bool startConsume;
        void consumeForAction(RightsParser& rightsParser, int action);
        void startConsumeForAction(RightsParser& rightsParser, int action);
    public:
        RightsConsumer();
        void setPlaybackStatus(int status, bool eof);
        bool consume(RightsParser& rightsParser);
        bool indicateConsume(RightsParser& rightsParser);
        bool shouldConsume();
        bool shouldIndicateConsume();
        virtual ~RightsConsumer();
    };

};

#endif  // RIGHTS_CONSUMER_HPP
