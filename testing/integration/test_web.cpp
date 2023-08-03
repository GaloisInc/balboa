#include <assert.h>
#include <curl/curl.h>
#include <fcntl.h>
#include <fmt/core.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <functional>
#include <iostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#ifdef NDEBUG
#error "NDEBUG must not be set"
#endif

namespace {
std::string env(const char* key) {
    const char* out = getenv(key);
    if (out == nullptr) {
        fprintf(stderr, "No such environment variable: %s", key);
        abort();
    }
    return std::string(out);
}

size_t ignore_data(void* buffer, size_t size, size_t nmemb, void* userp) {
    fprintf(stderr, "ingoring data\n");
    return nmemb;
}
size_t add_to_vector(void* buffer, size_t size, size_t nmemb, void* userp) {
    assert(userp != nullptr);
    auto dst = static_cast<std::vector<uint8_t>*>(userp);
    auto nbytes = size * nmemb;
    dst->resize(dst->size() + nbytes);
    memcpy(dst->data() + dst->size() - nbytes, buffer, nbytes);
    fprintf(stderr, "added bytes to vector %d\n", static_cast<int>(nbytes));
    return nmemb;
}

std::vector<uint8_t> read_file(const char* path) {
    auto fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "failed to open %s\n", path);
        perror("fopen()");
        abort();
    }
    std::vector<uint8_t> out;
    auto len = lseek(fd, 0, SEEK_END);
    assert(len >= 0);
    assert(lseek(fd, 0, SEEK_SET) == 0);
    out.resize(len);
    auto dst = out.data();
    while (len > 0) {
        auto delta = read(fd, dst, len);
        assert(delta > 0);
        len -= delta;
        dst += delta;
    }
    close(fd);
    return out;
}

template <typename A, typename B>
void assert_eq_internal(int line, const char* a_str, const char* b_str, const A& a, const B& b) {
    if (a != b) {
        auto msg = fmt::format("(Line {}) {} != {}; {} != {}", line, a_str, b_str, a, b);
        fprintf(stderr, "%s\n", msg.c_str());
        abort();
    }
}
}  // namespace

#define ASSERT_EQ(a, b) assert_eq_internal(__LINE__, #a, #b, a, b)

int main() {
    auto base_url = env("BASE_URL");
    auto static_root = env("STATIC_FILE_DIRECTORY");
    auto which_test = env("WHICH_TEST");

    assert(curl_global_init(CURL_GLOBAL_ALL) == 0);
    auto curl = curl_easy_init();
    assert(curl != nullptr);
    // curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");  // allow curl to use gzip encoding.
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, ignore_data);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl, CURLOPT_SSLVERSION,
                     CURL_SSLVERSION_MAX_TLSv1_2 | CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, fmt::format("test_web: {}", which_test).c_str());
    auto simple_test = [&]() {
        auto url = fmt::format("{}/test.txt", base_url);
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        std::vector<uint8_t> dst;
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, add_to_vector);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &dst);
        auto res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            abort();
        }
        auto canonical = read_file(fmt::format("{}/test.txt", static_root).c_str());
        ASSERT_EQ(canonical.size(), dst.size());
        assert(canonical == dst);
    };
    std::unordered_map<std::string, std::function<void()>> tests = {
        {"simple", simple_test},
        {"tls_session_resumption",
         [&]() {
             auto url = fmt::format("{}/nginx-connection-close", base_url);
             curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
             auto res = curl_easy_perform(curl);
             if (res != CURLE_OK) {
                 fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                 abort();
             }
             simple_test();
         }},
        {"connection_reuse",
         [&]() {
             simple_test();
             simple_test();
         }},
        {"connection_reuse_plik", [&]() {
             std::filesystem::path upload_root{env("UPLOAD_FILE_DIRECTORY")};
             std::vector<std::filesystem::path> paths_to_upload;
             for (auto const& dir_entry : std::filesystem::directory_iterator{upload_root}) {
                 paths_to_upload.push_back(dir_entry.path());
             }
             std::sort(paths_to_upload.begin(), paths_to_upload.end());
             curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
             for (auto const& path : paths_to_upload) {
                 // We'll leak the memory of the form... it's fine!
                 auto mime1 = curl_mime_init(curl);
                 auto part1 = curl_mime_addpart(mime1);
                 curl_mime_filedata(part1, path.c_str());
                 curl_mime_name(part1, "file");
                 auto url = fmt::format("{}/plik/", base_url);
                 curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
                 auto res = curl_easy_perform(curl);
                 if (res != CURLE_OK) {
                     fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
                     abort();
                 }
             }
         }}};
    if (tests.count(which_test) == 0) {
        fprintf(stderr, "UNKNOWN TEST: %s\n", which_test.c_str());
        abort();
    }
    tests[which_test]();
    curl_easy_cleanup(curl);
    return 0;
}