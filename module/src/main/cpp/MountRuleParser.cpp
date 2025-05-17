#include <fstream>
#include <sstream>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <string>
#include "log.h"

class MountRuleParser {
public:
	struct MountRule {
		std::vector<std::string> rootSubstrs;
		std::vector<std::string> mountPointSubstrs;
		std::unordered_set<std::string> fsTypes;
		std::vector<std::string> sources; // changed from unordered_set to vector for wildcard matching

		explicit operator bool() const {
			return !(rootSubstrs.empty() && mountPointSubstrs.empty() && fsTypes.empty() && sources.empty());
		}

		bool matches(const std::string& root, const std::string& mountPoint,
					 const std::string& fsType, const std::string& source) const {
			return matchList(rootSubstrs, root) &&
				   matchList(mountPointSubstrs, mountPoint) &&
				   (fsTypes.empty() || fsTypes.count(fsType) > 0) &&
				   matchSourceList(sources, source);
		}

		bool matches(const std::vector<std::string>& roots, const std::string& mountPoint,
					 const std::string& fsType, const std::string& source) const {
			if (!matchList(mountPointSubstrs, mountPoint) ||
				(!fsTypes.empty() && fsTypes.count(fsType) == 0) ||
				!matchSourceList(sources, source)) {
				return false;
			}
			for (const auto& root : roots) {
				if (matchList(rootSubstrs, root)) {
					return true;
				}
			}
			return false;
		}


	private:
		static bool match_with_wildcard(const std::string& value, const std::string& rawPattern) {
			std::string pattern;
			std::vector<bool> isEscaped;

			for (size_t i = 0; i < rawPattern.size(); ++i) {
				if (rawPattern[i] == '\\' && i + 1 < rawPattern.size()) {
					++i;
					pattern += rawPattern[i];
					isEscaped.push_back(true);
				} else {
					pattern += rawPattern[i];
					isEscaped.push_back(false);
				}
			}

			bool startsWithWildcard = !pattern.empty() && pattern.front() == '*' && !isEscaped[0];
			bool endsWithWildcard = !pattern.empty() &&
									pattern.back() == '*' &&
									!isEscaped[pattern.size() - 1];

			if (startsWithWildcard && endsWithWildcard && pattern.size() > 2) {
				return value.find(pattern.substr(1, pattern.size() - 2)) != std::string::npos;
			} else if (startsWithWildcard) {
				std::string suffix = pattern.substr(1);
				return value.size() >= suffix.size() &&
					   value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
			} else if (endsWithWildcard) {
				std::string prefix = pattern.substr(0, pattern.size() - 1);
				return value.compare(0, prefix.size(), prefix) == 0;
			} else {
				return value == pattern;
			}
		}

		static bool match_source_pattern(const std::string& value, const std::string& rawPattern) {
			std::string pattern;
			std::vector<bool> isEscaped;

			for (size_t i = 0; i < rawPattern.size(); ++i) {
				if (rawPattern[i] == '\\' && i + 1 < rawPattern.size()) {
					++i;
					pattern += rawPattern[i];
					isEscaped.push_back(true);
				} else {
					pattern += rawPattern[i];
					isEscaped.push_back(false);
				}
			}

			bool startsWithWildcard = !pattern.empty() && pattern.front() == '*' && !isEscaped[0];
			bool endsWithWildcard = !pattern.empty() &&
									pattern.back() == '*' &&
									!isEscaped[pattern.size() - 1];

			if (startsWithWildcard && endsWithWildcard && pattern.size() > 2) {
				return value.find(pattern.substr(1, pattern.size() - 2)) != std::string::npos;
			} else if (startsWithWildcard) {
				std::string suffix = pattern.substr(1);
				return value.size() >= suffix.size() &&
					   value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
			} else if (endsWithWildcard) {
				std::string prefix = pattern.substr(0, pattern.size() - 1);
				return value.compare(0, prefix.size(), prefix) == 0;
			} else {
				return value == pattern;
			}
		}

		static bool matchList(const std::vector<std::string>& patterns, const std::string& value) {
			if (patterns.empty()) return true;
			return std::any_of(patterns.begin(), patterns.end(),
							   [&](const std::string& p) { return match_with_wildcard(value, p); });
		}

		static bool matchSourceList(const std::vector<std::string>& patterns, const std::string& value) {
			if (patterns.empty()) return true;
			return std::any_of(patterns.begin(), patterns.end(),
							   [&](const std::string& p) { return match_source_pattern(value, p); });
		}
	};

	// Not necessary anymore
	struct MountEntry {
		std::string root;
		std::string mountPoint;
		std::string fsType;
		std::string mountSource;
	};

	// Used previously for testing its effectiveness
	static MountEntry parseMountinfo(const std::string& line) {
		std::istringstream iss(line);
		std::vector<std::string> tokens;
		std::string token;

		while (iss >> token) tokens.push_back(token);

		auto sep = std::find(tokens.begin(), tokens.end(), "-");
		if (sep == tokens.end() || std::distance(tokens.begin(), sep) < 6) {
			LOGE("[MountRuleParser::parseMultipleRules]: Malformed mountinfo line");
			return {};
		}

		MountEntry entry;
		entry.root = tokens[3];
		entry.mountPoint = tokens[4];
		entry.fsType = *(sep + 1);
		entry.mountSource = *(sep + 2);
		return entry;
	}

	static MountRule parseRuleString(const std::string& ruleText) {
		if (!validateSyntax(ruleText)) {
			return {};
		}

		MountRule rule;
		auto tokens = tokenizePreserveQuotes(ruleText);

		enum Section { NONE, ROOT, POINT, FS, SOURCE } current = NONE;
		enum State { WRITING, IDLE } state = IDLE;

		for (std::string& word : tokens) {
			if (state == IDLE) {
				if (current == NONE) {
					if (word == "root") current = ROOT;
					else if (word == "point") current = POINT;
					else if (word == "fs") current = FS;
					else if (word == "source") current = SOURCE;
				} else if (word == "{") {
					state = WRITING;
				}
			} else if (state == WRITING && word == "}") {
				current = NONE;
				state = IDLE;
			} else {
				if ((word.front() == '"' && word.back() == '"') ||
					(word.front() == '\'' && word.back() == '\'')) {
					word = word.substr(1, word.size() - 2);
				}

				switch (current) {
					case ROOT:
						rule.rootSubstrs.push_back(word);
						break;
					case POINT:
						rule.mountPointSubstrs.push_back(word);
						break;
					case FS:
						rule.fsTypes.insert(word);
						break;
					case SOURCE:
						rule.sources.push_back(word); // changed from insert() to push_back()
						break;
					default:
						break;
				}
			}
		}

		return rule;
	}

	static std::vector<MountRule> parseMultipleRules(const std::vector<std::string>& ruleTexts) {
		std::vector<MountRule> rules;
		for (const auto& text : ruleTexts) {
			MountRule rule = parseRuleString(text);
			if (rule) {
				rules.push_back(rule);
			} else {
				LOGE("[MountRuleParser::parseMultipleRules]: Failed to parse rule: `%s`", text.c_str());
			}
		}
		return rules;
	}

private:
	static bool validateSyntax(const std::string& text) {
		int braceCount = 0;
		bool inDoubleQuotes = false, inSingleQuotes = false;

		for (size_t i = 0; i < text.size(); ++i) {
			char ch = text[i];
			if (ch == '"' && !inSingleQuotes && (i == 0 || text[i - 1] != '\\'))
				inDoubleQuotes = !inDoubleQuotes;
			else if (ch == '\'' && !inDoubleQuotes && (i == 0 || text[i - 1] != '\\'))
				inSingleQuotes = !inSingleQuotes;

			if (!inDoubleQuotes && !inSingleQuotes) {
				if (ch == '{') ++braceCount;
				else if (ch == '}') {
					--braceCount;
					if (braceCount < 0) return false;
				}
			}
		}

		return braceCount == 0 && !inDoubleQuotes && !inSingleQuotes;
	}

	static std::vector<std::string> tokenizePreserveQuotes(const std::string& text) {
		std::vector<std::string> tokens;
		std::string current;
		bool inQuotes = false;
		char quoteChar = '\0';

		for (size_t i = 0; i < text.length(); ++i) {
			char c = text[i];

			if ((c == '"' || c == '\'') && (i == 0 || text[i - 1] != '\\')) {
				if (!inQuotes) {
					inQuotes = true;
					quoteChar = c;
					current += c;
				} else if (c == quoteChar) {
					inQuotes = false;
					current += c;
					tokens.push_back(current);
					current.clear();
				} else {
					current += c;
				}
			} else if (std::isspace(c) && !inQuotes) {
				if (!current.empty()) {
					tokens.push_back(current);
					current.clear();
				}
			} else {
				current += c;
			}
		}

		if (!current.empty()) tokens.push_back(current);
		return tokens;
	}
};
