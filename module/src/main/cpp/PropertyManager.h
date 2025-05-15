#ifndef NOHELLO_PROPERTYMANAGER_H
#define NOHELLO_PROPERTYMANAGER_H

#include <string>
#include <unordered_map>
#include <vector>

class PropertyManager {
public:
	explicit PropertyManager(std::string  path);

	std::string getProp(const std::string& key, const std::string& defaultValue = "");
	void setProp(const std::string& key, const std::string& value);
  // bool hasProp(const std::string& key) const;
  // void removeProp(const std::string& key);

private:
	std::string filePath;

	// Maintain insertion order
	std::vector<std::pair<std::string, std::string>> orderedProps;

	// Fast lookup: key -> index in orderedProps
	std::unordered_map<std::string, size_t> keyIndex;

	bool loadFromFile();
	bool saveToFile();
};

#endif //NOHELLO_PROPERTYMANAGER_H
