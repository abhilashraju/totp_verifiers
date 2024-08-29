#pragma once
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <stdint.h>
#include <string.h>

#include <chrono>
#include <ctime>
#include <format>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
namespace bmcweb
{
class Base32
{
    constexpr static int BITS_PER_BASE32_CHAR = 5;

  public:
    static std::string decode(std::string_view src)
    {
        const uint8_t* encoded = (const uint8_t*)src.data();
        auto secretLen = (src.length() + 7) / 8 * BITS_PER_BASE32_CHAR;
        constexpr int bufSize = 100;
        if (secretLen <= 0 || secretLen > bufSize)
        {
            return std::string();
        }
        std::string result(bufSize, '\000');
        unsigned int buffer = 0;
        int bitsLeft = 0;
        size_t count = 0;
        for (const uint8_t* ptr = encoded; count < bufSize && *ptr; ++ptr)
        {
            uint8_t ch = *ptr;
            if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' ||
                ch == '-')
            {
                continue;
            }
            buffer <<= 5;

            // Deal with commonly mistyped characters
            if (ch == '0')
            {
                ch = 'O';
            }
            else if (ch == '1')
            {
                ch = 'L';
            }
            else if (ch == '8')
            {
                ch = 'B';
            }

            // Look up one base32 digit
            if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z'))
            {
                ch = (ch & 0x1F) - 1;
            }
            else if (ch >= '2' && ch <= '7')
            {
                ch -= '2' - 26;
            }
            else
            {
                return std::string();
            }

            buffer |= ch;
            bitsLeft += 5;
            if (bitsLeft >= 8)
            {
                result[count++] = static_cast<char>(buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }
        if (count < bufSize)
        {
            result.resize(count);
        }
        return result;
    }
};

struct Totp
{
    constexpr static int VERIFICATION_CODE_MODULUS = 1000000;
    constexpr static int SHA1_DIGEST_LENGTH = 20;
    std::string secret;
    time_t stepSize{30};
    Totp& loadSecret(const std::string& userName)
    {
        std::string filePath = std::format("/home/{}/.google_authenticator",
                                           userName);
        std::ifstream file(filePath);
        if (file.is_open())
        {
            std::getline(file, secret);
            file.close();
        }
        return *this;
    }
    Totp& loadSecret(std::ifstream& stream)
    {
        if (stream.is_open())
        {
            stream.seekg(0, std::ios::beg);
            std::getline(stream, secret);
            stream.close();
        }
        return *this;
    }
    static std::string timeToDateTimeString(time_t time)
    {
        // Convert time_t to tm structure
        std::tm* tm_ptr =
            std::localtime(&time); // Use std::gmtime(&time) for UTC
        std::ostringstream oss;
        oss << std::put_time(tm_ptr, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }
    auto totpTimeNow(time_t offset) const -> time_t
    {
        auto t = std::chrono::system_clock::now();
        auto seconds_since_epoch =
            std::chrono::duration_cast<std::chrono::seconds>(
                t.time_since_epoch())
                .count();

        // Add the offset in seconds
        seconds_since_epoch += offset;

        auto t_divided = seconds_since_epoch / stepSize;
        BMCWEB_LOG_DEBUG("TOTP time now: {}",
                         timeToDateTimeString(seconds_since_epoch));
        return t_divided;
    }
    std::string now(time_t offset = 0) const
    {
        if (secret.empty())
        {
            return "Secret not found";
        }
        return std::format("{:06}",
                           generateCode(secret.data(), totpTimeNow(offset)));
    }
    std::string after(time_t sec) const
    {
        return std::format("{:06}",
                           generateCode(secret.data(), totpTimeNow(0) + sec));
    }
    static unsigned int generateCode(const char* key, time_t tm)
    {
        uint8_t challenge[8];
        for (int i = 8; i--; tm >>= 8)
        {
            challenge[i] = static_cast<uint8_t>(tm);
        }

        auto secret = Base32::decode(key);

        unsigned int len = SHA_DIGEST_LENGTH;
        uint8_t hash[SHA_DIGEST_LENGTH]{0};
        HMAC(EVP_sha1(), secret.data(), static_cast<int>(secret.length()),
             challenge, 8, hash, &len);
        // Pick the offset where to sample our hash value for the actual
        // verification code.
        const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;

        // Compute the truncated hash in a byte-order independent loop.
        unsigned int truncatedHash = 0;
        for (int i = 0; i < 4; ++i)
        {
            truncatedHash <<= 8;
            truncatedHash |= hash[offset + i];
        }

        // Truncate to a smaller number of digits.
        truncatedHash &= 0x7FFFFFFF;
        truncatedHash %= VERIFICATION_CODE_MODULUS;

        return truncatedHash;
    }

    bool verify(const std::string& totp)
    {
        time_t windowsize = 3;
        for (time_t i = -(windowsize - 1) / 2; i <= windowsize / 2; i++)
        {
            std::string expectedtotp = now(i * stepSize);
            if (totp == expectedtotp)
            {
                return true;
            }
        }
        BMCWEB_LOG_ERROR("TOTP verification failded for {}", totp);
        return false;
    }
};
} // namespace bmcweb
