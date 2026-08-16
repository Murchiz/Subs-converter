#include <string>
#include <string_view>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <print>

namespace fs = std::filesystem;

int main(int argc, char* argv[]) {
    // Try to find reference/meta.yaml - check multiple locations
    std::string meta_path;
    
    // Build search paths
    std::vector<fs::path> search_dirs;
    
    // From executable directory
    if (argc > 0 && argv[0]) {
        fs::path exe_dir = fs::path(argv[0]).parent_path();
        search_dirs.push_back(exe_dir / "reference");
        search_dirs.push_back(exe_dir / "../tests/reference");
        search_dirs.push_back(exe_dir / "../../tests/reference");
    }
    
    // Relative paths
    search_dirs.emplace_back("tests/reference");
    search_dirs.emplace_back("reference");
    
    for (const auto& dir : search_dirs) {
        fs::path candidate = dir / "meta.yaml";
        if (fs::exists(candidate)) {
            meta_path = candidate.string();
            break;
        }
    }
    
    if (meta_path.empty()) {
        std::println(stderr, "reference/meta.yaml not found");
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
            if (search_pos < payload.length() && isalpha(static_cast<unsigned char>(payload[search_pos]))) {
                next_section = search_pos;
                break;
            }
        }
        size_t p_end = (next_section != std::string::npos) ? next_section : payload.length();
        
        std::string_view block = std::string_view(payload).substr(p_start, p_end - p_start);
        
        std::string filtered_block;
        size_t search_start = 0;
        while (true) {
            size_t name_pos = block.find("- name:", search_start);
            if (name_pos == std::string_view::npos) break;
            
            size_t node_start = name_pos;
            while (node_start > 0 && (block[node_start - 1] == ' ' || block[node_start - 1] == '\t')) {
                node_start--;
            }
            
            size_t next_name_pos = block.find("- name:", name_pos + 7);
            size_t next_node_start = block.length();
            if (next_name_pos != std::string_view::npos) {
                next_node_start = next_name_pos;
                while (next_node_start > node_start && (block[next_node_start - 1] == ' ' || block[next_node_start - 1] == '\t')) {
                    next_node_start--;
                }
            }
            
            std::string_view node_str = block.substr(node_start, next_node_start - node_start);
            
            // Drop unsupported xhttp nodes
            if (!node_str.contains("xhttp")) {
                filtered_block.append(node_str);
                
                size_t n_pos = node_str.find("- name:");
                size_t end_line = node_str.find('\n', n_pos);
                if (end_line == std::string_view::npos) end_line = node_str.length();
                size_t q_start = node_str.find_first_not_of(" \t'\"", n_pos + 7);
                size_t q_end = node_str.find_last_not_of(" \t\r\n'\"", end_line - 1);
                if (q_start != std::string_view::npos && q_end != std::string_view::npos && q_start <= q_end) {
                    raw_clash_names += std::format("      - \"{}\"\n", node_str.substr(q_start, q_end - q_start + 1));
                }
            }
            search_start = next_name_pos;
        }
        raw_clash_proxies += filtered_block;
    }
    
    std::println("--- RAW CLASH PROXIES ---");
    std::println("{}", raw_clash_proxies);
    std::println("--- RAW CLASH NAMES ---");
    std::println("{}", raw_clash_names);
    return 0;
}
