#include "PropertyManager.h"
#include <fstream>
#include <sstream>
#include <utility>
//#include "log.h"

PropertyManager::PropertyManager(std::string path) : filePath(std::move(path)) {
	loadFromFile();
}

bool PropertyManager::loadFromFile() {
	orderedProps.clear();
	keyIndex.clear();

	std::ifstream file(filePath);
	if (!file.is_open()) {
		//LOGW("PropertyManager: Could not open %s for loading.", filePath.c_str());
		return false;
	}

	std::string line;
	while (std::getline(file, line)) {
		if (line.empty() || line[0] == '#')
			continue;

		auto pos = line.find('=');
		if (pos == std::string::npos)
			continue;

		std::string key = line.substr(0, pos);
		std::string val = line.substr(pos + 1);

		size_t idx = orderedProps.size();
		orderedProps.emplace_back(key, val);
		keyIndex[key] = idx;
	}

	file.close();
	return true;
}

bool PropertyManager::saveToFile() {
	std::ofstream file(filePath, std::ios::trunc);
	if (!file.is_open()) {
		//LOGE("PropertyManager: Could not open %s for saving.", filePath.c_str());
		return false;
	}

	for (const auto& [key, value] : orderedProps) {
		file << key << "=" << value << '\n';
	}

	file.close();
	return true;
}

std::string PropertyManager::getProp(const std::string& key, const std::string& defaultValue) {
	auto it = keyIndex.find(key);
	return it != keyIndex.end() ? orderedProps[it->second].second : defaultValue;
}

void PropertyManager::setProp(const std::string& key, const std::string& value) {
	auto it = keyIndex.find(key);
	if (it != keyIndex.end()) {
		// Update existing
		orderedProps[it->second].second = value;
	} else {
		// Append new
		size_t idx = orderedProps.size();
		orderedProps.emplace_back(key, value);
		keyIndex[key] = idx;
	}

	saveToFile();
}

/* Optional implementations if needed later
bool PropertyManager::hasProp(const std::string& key) const {
    return props.count(key);
}

void PropertyManager::removeProp(const std::string& key) {
    props.erase(key);
    saveToFile();
}
*/
