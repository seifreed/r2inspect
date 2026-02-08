from r2inspect.modules import (
    compiler_domain,
    crypto_domain,
    elf_domain,
    elf_security_domain,
    macho_domain,
    macho_security_domain,
    pe_info_domain,
    rich_header_domain,
    similarity_scoring,
    string_domain,
)


def test_compiler_domain_helpers():
    signatures = {
        "strings": ["gcc"],
        "imports": ["msvcrt"],
        "sections": [".text"],
        "symbols": ["main"],
    }
    score = compiler_domain.calculate_compiler_score(
        signatures,
        ["GCC 9.1"],
        ["msvcrt.dll"],
        [".text"],
        ["main"],
    )
    assert score > 0

    method = compiler_domain.detection_method("MSVC", 0.9)
    assert "Runtime" in method

    assert compiler_domain.map_msvc_version_from_rich("2019") == "Visual Studio 2019"
    assert compiler_domain.detect_msvc_version(["Microsoft Visual C++ 19.0"], [], {})
    assert compiler_domain.detect_gcc_version(["GCC 9.3.0"]) == "GCC 9.3.0"
    assert compiler_domain.detect_clang_version(["clang version 10.0.0"]) == "Clang 0.0.0"
    assert compiler_domain.detect_go_version(["go1.20.1"]) == "Go 1.20.1"
    assert compiler_domain.detect_rust_version(["rustc 1.70.0"]) == "Rust 1.70.0"

    strings = compiler_domain.parse_strings_output("0x1 0 0 0 gcc\n")
    assert strings == ["gcc"]

    imports = compiler_domain.extract_import_names(
        [{"libname": "KERNEL32"}, {"name": "CreateFile"}]
    )
    assert "KERNEL32" in imports and "CreateFile" in imports

    sections = compiler_domain.extract_section_names([{"name": ".text"}])
    assert sections == [".text"]

    symbols = compiler_domain.extract_symbol_names([{"name": "main"}])
    assert symbols == ["main"]


def test_crypto_domain_helpers():
    detected = {}
    crypto_domain.detect_algorithms_from_strings([{"string": "AES", "vaddr": 1}], detected)
    assert "AES" in detected

    consolidated = crypto_domain.consolidate_detections(detected)
    assert consolidated[0]["algorithm"] == "AES"

    assert crypto_domain._is_candidate_string("a") is False
    assert crypto_domain._is_candidate_string("vector.deleting.destructor") is False


def test_elf_domain_helpers():
    info = elf_domain.parse_comment_compiler_info("GCC: (GNU) 9.3.0")
    assert info["compiler"] == "GCC 9.3.0"

    dwarf = elf_domain.parse_dwarf_info(
        ["DW_AT_producer: GNU C 9.3.0", "DW_AT_comp_dir 2023-01-01"]
    )
    assert "compiler" in dwarf and "compile_time" in dwarf

    assert elf_domain.parse_dwarf_compile_time("compilation 2023-01-01") == "2023-01-01"
    assert elf_domain.parse_build_id_data("Build ID: ab cd ef 01 02 03") == "0203"

    section = elf_domain.find_section_by_name([{"name": ".text"}], "text")
    assert section["name"] == ".text"

    assert elf_domain.build_section_read_commands({"vaddr": 1, "size": 2}, "pxj") == (
        "s 1",
        "pxj 2",
    )


def test_elf_security_domain_helpers():
    assert elf_security_domain.has_nx([{"type": "GNU_STACK", "flags": "rw"}]) is True
    assert elf_security_domain.has_stack_canary([{"name": "__stack_chk_fail"}]) is True
    assert elf_security_domain.has_relro("BIND_NOW") is True
    assert elf_security_domain.is_pie({"bin": {"class": "DYN"}}) is True
    assert elf_security_domain.path_features("RPATH RUNPATH") == {"rpath": True, "runpath": True}


def test_macho_domain_helpers():
    assert macho_domain.estimate_from_sdk_version("14.0") == "~2023 (SDK 14.0)"
    assert macho_domain.platform_from_version_min("MACOSX") == "macOS"
    assert macho_domain.dylib_timestamp_to_string(0) == (None, None)

    commands = macho_domain.build_load_commands([{"type": "LC", "size": 1}])
    assert commands[0]["type"] == "LC"

    sections = macho_domain.build_sections([{"name": "__text", "segment": "__TEXT"}])
    assert sections[0]["segment"] == "__TEXT"


def test_macho_security_domain_helpers():
    assert macho_security_domain.is_pie({"bin": {"filetype": "PIE"}}) is True
    assert macho_security_domain.has_stack_canary([{"name": "___stack_chk_fail"}]) is True
    assert macho_security_domain.has_arc([{"name": "_objc_retain"}]) is True
    assert (
        macho_security_domain.is_encrypted([{"type": "LC_ENCRYPTION_INFO", "cryptid": 1}]) is True
    )
    assert macho_security_domain.is_signed([{"type": "LC_CODE_SIGNATURE"}]) is True


def test_pe_info_domain_helpers():
    assert pe_info_domain.determine_pe_file_type({"class": "PE32"}, None, "dll") == "DLL"
    assert pe_info_domain.determine_pe_format({"format": "PE"}, None) == "PE"
    assert pe_info_domain.normalize_pe_format("PE32+") == "PE"

    entry = pe_info_domain.compute_entry_point({"baddr": 1, "boffset": 2}, [{"vaddr": 10}])
    assert entry == 10

    info = pe_info_domain.apply_optional_header_info(
        {"image_base": 1, "entry_point": 0},
        {"optional_header": {"ImageBase": 2, "AddressOfEntryPoint": 3}},
    )
    assert info["image_base"] == 2
    assert info["entry_point"] == 5

    flags = pe_info_domain.characteristics_from_header({"file_header": {"Characteristics": 0x2002}})
    assert flags["is_dll"] is True
    assert flags["is_executable"] is True

    normalized = pe_info_domain.normalize_resource_entries([{"name": "X"}])
    assert normalized[0]["name"] == "X"

    parsed = pe_info_domain.parse_version_info_text("Company=ACME\n")
    assert parsed["Company"] == "ACME"


def test_rich_header_and_similarity_and_string_domains():
    assert rich_header_domain.parse_clear_data_entries(b"") == []

    assert similarity_scoring.jaccard_similarity(set(), set()) == 1.0
    assert similarity_scoring.jaccard_similarity({1}, set()) == 0.0
    assert similarity_scoring.normalized_difference_similarity(10, 5) > 0

    filtered = string_domain.filter_strings(["abc", "\x00"], 2, 10)
    assert "abc" in filtered

    assert string_domain.parse_search_results("0x1 00\n") == ["0x1"]
    assert string_domain.xor_string("A", 1) != "A"

    matches = string_domain.build_xor_matches("A", lambda _hex: "0x1")
    assert matches

    suspicious = string_domain.find_suspicious(["http://example.com"])
    assert suspicious

    assert string_domain.is_base64("QUJDRA==") is True
    assert string_domain.decode_base64("QUJDRA==")["decoded"] == "ABCD"

    assert string_domain.is_hex("4142") is True
    assert string_domain.decode_hex("4142")["decoded"] == "AB"
