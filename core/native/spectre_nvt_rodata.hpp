// SPECTRE C++17 v9.0 Static .rodata NVT & Favicon Header
#pragma once
#include <cstddef>
#include <cstdint>
namespace spectre_rodata {
struct FaviconSpec { int32_t mmh3; const char* product; };
struct NativeNvtSpec {
    const char* id; const char* title; const char* category;
    const char* severity; uint16_t cvss_x10; const char* cwe; const char* path;
    int32_t status; const char* match_tok0; const char* match_tok1; const char* mandatory_gate;
};
uint32_t nvt_part2_count();
} // namespace spectre_rodata
