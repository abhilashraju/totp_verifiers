#pragma once
#include <security/pam_appl.h>
#include <stdio.h>
#include <stdlib.h>

#include <cstring>
#include <format>
#include <span>
#include <string>
namespace bmcweb
{
struct Totp
{
    // function used to get user input
    static int pamFunctionConversation(int numMsg,
                                       const struct pam_message** msg,
                                       struct pam_response** resp,
                                       void* appdataPtr)
    {
        if ((appdataPtr == nullptr) || (msg == nullptr) || (resp == nullptr))
        {
            return PAM_CONV_ERR;
        }

        if (numMsg <= 0 || numMsg >= PAM_MAX_NUM_MSG)
        {
            return PAM_CONV_ERR;
        }

        auto msgCount = static_cast<size_t>(numMsg);
        auto messages = std::span(msg, msgCount);
        auto responses = std::span(resp, msgCount);

        for (size_t i = 0; i < msgCount; ++i)
        {
            /* Ignore all PAM messages except prompting for hidden input */
            if (messages[i]->msg_style != PAM_PROMPT_ECHO_OFF)
            {
                continue;
            }

            /* Assume PAM is only prompting for the password as hidden input */
            /* Allocate memory only when PAM_PROMPT_ECHO_OFF is encounterred */

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            char* appPass = reinterpret_cast<char*>(appdataPtr);
            size_t appPassSize = std::strlen(appPass);

            if ((appPassSize + 1) > PAM_MAX_RESP_SIZE)
            {
                return PAM_CONV_ERR;
            }
            // IDeally we'd like to avoid using malloc here, but because we're
            // passing off ownership of this to a C application, there aren't a
            // lot of sane ways to avoid it.

            // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
            void* passPtr = malloc(appPassSize + 1);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            char* pass = reinterpret_cast<char*>(passPtr);
            if (pass == nullptr)
            {
                return PAM_BUF_ERR;
            }

            std::strncpy(pass, appPass, appPassSize + 1);

            size_t numMsgSize = static_cast<size_t>(numMsg);
            // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
            void* ptr = calloc(numMsgSize, sizeof(struct pam_response));
            if (ptr == nullptr)
            {
                // NOLINTNEXTLINE(cppcoreguidelines-no-malloc)
                free(pass);
                return PAM_BUF_ERR;
            }

            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            *resp = reinterpret_cast<pam_response*>(ptr);
            responses[i]->resp = pass;
            return PAM_SUCCESS;
        }

        return PAM_CONV_ERR;
    }

    Totp(const std::string& ser, const std::string& u, const std::string& t) :
        service(ser), username(u), totp(t),
        localConversation(pamFunctionConversation, totp.data())
    {
        int retval = pam_start(service.data(), username.data(),
                               &localConversation, &pamh);
        if (retval != PAM_SUCCESS)
        {
            BMCWEB_LOG_ERROR("Pam start failed for {}", service.data());
            pamh = nullptr;
        }
    }
    ~Totp()
    {
        if (pamh != nullptr)
        {
            if (pam_end(pamh, PAM_SUCCESS) != PAM_SUCCESS)
            {
                BMCWEB_LOG_ERROR("Pam end failed for {}", service.data());
            }
        }
    }
    bool verify()
    {
        if (pamh != nullptr)
        {
            return (pam_authenticate(pamh, 0) == PAM_SUCCESS);
        }
        return false;
    }
    std::string service;
    std::string username;
    std::string totp;
    pam_conv localConversation;
    pam_handle_t* pamh{nullptr};
};
} // namespace bmcweb
