/**
 * Copyright Spack Project Developers. See COPYRIGHT file for details.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR MIT)
 */
#pragma once

/**
 * Regex helpers, kept out of utils.h so that <regex> - the heaviest header in
 * the standard library - is only compiled into the translation units that
 * actually match against text (currently just the relocation path).
 */

#include <regex>
#include <string>
#include <vector>

/// @brief Searches a sections of a string for a given regex using provided
///     options to control search behavior
/// @param searchDomain - string to be searched
/// @param regex - regex used to search
/// @param opts - optional argument, list of regex tuning options to adapt the search behavior
/// @return Character sequence matching search regex
std::smatch regexSearch(
    const std::string& searchDomain, const std::string& regex,
    const std::vector<std::regex_constants::syntax_option_type>& opts = {},
    const std::vector<std::regex_constants::match_flag_type>& flags = {});

/// @brief Tries to match an entire string to a given regex using provided
///     options to control match behavior
/// @param searchDomain - string to be matched
/// @param regex - regex used to match
/// @param opts - optional argument, list of regex tuning options to adapt the match behavior
/// @return Character sequence matching regex
std::smatch regexMatch(
    const std::string& searchDomain, const std::string& regex,
    const std::vector<std::regex_constants::syntax_option_type>& opts = {},
    const std::vector<std::regex_constants::match_flag_type>& flags = {});

/// @brief Searches a string for a given regex using provided
///     options to control search behavior, and if found, replaces
///     discovered string with given replacement string
/// @param searchDomain - string to be searched
/// @param regex - regex used to search
/// @param replacement - string used to replace regex matched result
/// @param opts - optional argument, list of regex tuning options to adapt the search behavior
/// @return Character sequence matching search regex
std::string regexReplace(
    const std::string& replaceDomain, const std::string& regex,
    const std::string& replacement,
    const std::vector<std::regex_constants::syntax_option_type>& opts = {},
    const std::vector<std::regex_constants::match_flag_type>& flags = {});
