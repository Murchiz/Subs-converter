#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <cstdlib>

int main(int argc, char* argv[]) {
    // Try to find reference/meta.yaml - check multiple locations
    std::string meta_path;
    
    // Build search paths
    std::vector<std::string> search_dirs;
    
    // From executable directory
    if (argc > 0 && argv[0]) {
        std::string exe_path = argv[0];
        size_t pos = exe_path.find_last_of("/\\");
        if (pos != std::string::npos) {
            std::string exe_dir = exe_path.substr(0, pos);
            search_dirs.push_back(exe_dir + "/reference");
            search_dirs.push_back(exe_dir + "/../tests/reference");
            search_dirs.push_back(exe_dir + "/../../tests/reference");
        }
    }
    
    // Relative paths
    search_dirs.push_back("tests/reference");
    search_dirs.push_back("reference");
    
    for (const auto& dir : search_dirs) {
        std::string candidate = dir + "/meta.yaml";
        std::ifstream test_file(candidate);
        if (test_file.good()) {
            meta_path = candidate;
            break;
        }
    }
    
    if (meta_path.empty()) {
        std::cerr << "reference/meta.yaml not found" << std::endl;
        return 1;
    }
    
    std::ifstream file(meta_path);
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string payload = buffer.str();
    
    std::string raw_clash_proxies;
    std::string raw_clash_names;
    
    size_t p_start = payload.find("proxies:");
    if (p_start != std::string::npos) {
        p_start += 8; // skip 'proxies:'
        if (p_start < payload.length() && payload[p_start] == '\r') p_start++;
        if (p_start < payload.length() && payload[p_start] == '\n') p_start++;
        
        size_t next_section = std::string::npos;
        size_t search_pos = p_start;
        while ((search_pos = payload.find('\n', search_pos)) != std::string::npos) {
            search_pos++;
            if (search_pos < payload.length() && isalpha((unsigned char)payload[search_pos])) {
                next_section = search_pos;
                break;
            }
        }
        size_t p_end = (next_section != std::string::npos) ? next_section : payload.length();
        
        std::string block = payload.substr(p_start, p_end - p_start);
        
        std::string filtered_block;
        size_t search_start = 0;
        while (true) {
            size_t name_pos = block.find("- name:", search_start);
            if (name_pos == std::string::npos) break;
            
            size_t node_start = name_pos;
            while (node_start > 0 && (block[node_start - 1] == ' ' || block[node_start - 1] == '\t')) {
                node_start--;
            }
            
            size_t next_name_pos = block.find("- name:", name_pos + 7);
            size_t next_node_start = block.length();
            if (next_name_pos != std::string::npos) {
                next_node_start = next_name_pos;
                while (next_node_start > node_start && (block[next_node_start - 1] == ' ' || block[next_node_start - 1] == '\t')) {
                    next_node_start--;
                }
            }
            
            std::string node_str = block.substr(node_start, next_node_start - node_start);
            
            // Drop unsupported xhttp nodes
            if (node_str.find("xhttp") == std::string::npos) {
                filtered_block += node_str;
                
                size_t n_pos = node_str.find("- name:");
                size_t end_line = node_str.find('\n', n_pos);
                if (end_line == std::string::npos) end_line = node_str.length();
                size_t q_start = node_str.find_first_not_of(" \t'\"", n_pos + 7);
                size_t q_end = node_str.find_last_not_of(" \t\r\n'\"", end_line - 1);
                if (q_start != std::string::npos && q_end != std::string::npos && q_start <= q_end) {
                    raw_clash_names += "      - \"" + node_str.substr(q_start, q_end - q_start + 1) + "\"\n";
                }
            }
            search_start = next_name_pos;
        }
        raw_clash_proxies += filtered_block;
    }
    
    std::cout << "--- RAW CLASH PROXIES ---\n";
    std::cout << raw_clash_proxies << "\n";
    std::cout << "--- RAW CLASH NAMES ---\n";
    std::cout << raw_clash_names << "\n";
    return 0;
}
