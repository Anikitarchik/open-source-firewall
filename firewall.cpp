#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>
#include <arpa/inet.h>
#include <map>
#include <vector>
#include <thread>
#include <mutex>
#include <ctime>
#include <fstream>
#include <sstream>
#include <atomic>

std::mutex rules_mutex;

// Файл конфигурации
const std::string CONFIG_FILE = "firewall_rules.txt";

// Правила блокировки
struct Rule {
    std::string ip;
    int port; // -1 для любого порта
    int protocol; // 1 = TCP, 2 = UDP, 0 = любой
    std::pair<int, int> time_range; // {начало, конец} (часы)
};

std::vector<Rule> rules;

// Для защиты от DoS
std::map<std::string, int> ip_packet_count;
std::mutex dos_mutex;

// Лимит пакетов от одного IP в секунду
const int DOS_PACKET_LIMIT = 100;

std::atomic<bool> running(true);

// Функция для записи правил в файл
void saveRulesToFile() {
    std::lock_guard<std::mutex> lock(rules_mutex);
    std::ofstream file(CONFIG_FILE, std::ios::trunc);
    if (!file.is_open()) {
        std::cerr << "[ERROR] Не удалось открыть файл для записи: " << CONFIG_FILE << std::endl;
        return;
    }

    for (const auto& rule : rules) {
        file << rule.ip << " " << rule.port << " " << rule.protocol << " "
             << rule.time_range.first << " " << rule.time_range.second << "\n";
    }
    file.close();
    std::cout << "[INFO] Конфигурация успешно сохранена в " << CONFIG_FILE << std::endl;
}

// Функция для загрузки правил из файла
void loadRulesFromFile() {
    std::lock_guard<std::mutex> lock(rules_mutex);
    std::ifstream file(CONFIG_FILE);
    if (!file.is_open()) {
        std::cerr << "[WARNING] Файл конфигурации не найден: " << CONFIG_FILE << std::endl;
        return;
    }

    rules.clear();
    Rule rule;
    while (file >> rule.ip >> rule.port >> rule.protocol >> rule.time_range.first >> rule.time_range.second) {
        rules.push_back(rule);
    }
    file.close();
    std::cout << "[INFO] Правила загружены из " << CONFIG_FILE << std::endl;
}

// Проверка времени
bool isWithinTimeRange(const std::pair<int, int>& range) {
    time_t now = time(nullptr);
    tm* local_time = localtime(&now);
    int current_hour = local_time->tm_hour;

    return current_hour >= range.first && current_hour < range.second;
}

// Проверка, нужно ли блокировать пакет
bool shouldBlockPacket(const struct iphdr* ip_header, int src_port, int protocol) {
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);

    std::lock_guard<std::mutex> lock(rules_mutex);

    for (const auto& rule : rules) {
        // Проверяем IP
        if (rule.ip != "any" && rule.ip != source_ip) continue;

        // Проверяем порт
        if (rule.port != -1 && rule.port != src_port) continue;

        // Проверяем протокол
        if (rule.protocol != 0 && rule.protocol != protocol) continue;

        // Проверяем время
        if (!isWithinTimeRange(rule.time_range)) continue;

        return true; // Пакет должен быть заблокирован
    }

    return false;
}

// Защита от DoS
bool isDoSAttack(const char* source_ip) {
    std::lock_guard<std::mutex> lock(dos_mutex);

    ip_packet_count[source_ip]++;
    if (ip_packet_count[source_ip] > DOS_PACKET_LIMIT) {
        return true;
    }
    return false;
}

// Сброс счетчика DoS каждые 1 секунду
void resetDoSCounters() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        std::lock_guard<std::mutex> lock(dos_mutex);
        ip_packet_count.clear();
    }
}

// Добавление правила через консоль
void addRule() {
    Rule rule;
    std::cout << "Введите IP-адрес для блокировки (или \"any\" для любого): ";
    std::cin >> rule.ip;

    std::cout << "Введите порт для блокировки (-1 для любого): ";
    std::cin >> rule.port;

    std::cout << "Введите протокол (1 = TCP, 2 = UDP, 0 = любой): ";
    std::cin >> rule.protocol;

    std::cout << "Введите время начала (час, 0-23): ";
    std::cin >> rule.time_range.first;

    std::cout << "Введите время конца (час, 0-23): ";
    std::cin >> rule.time_range.second;

    {
        std::lock_guard<std::mutex> lock(rules_mutex);
        rules.push_back(rule);
    }
    saveRulesToFile(); // Сохранение в файл
    std::cout << "Правило добавлено успешно!" << std::endl;
}

// Обработчик пакетов
void packetHandler(u_char* user, const struct pcap_pkthdr* header, const u_char* packet) {
    const struct iphdr* ip_header = (struct iphdr*)(packet + 14);

    // Проверяем, является ли пакет IPv4
    if (ip_header->version != 4) return;

    // Определяем источник
    char source_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), source_ip, INET_ADDRSTRLEN);

    // Проверка на DoS-атаку
    if (isDoSAttack(source_ip)) {
        std::cout << "[DoS BLOCKED] Excessive packets from IP: " << source_ip << std::endl;
        return;
    }

    // Проверка порта и протокола
    int protocol = (ip_header->protocol == IPPROTO_TCP) ? 1 : (ip_header->protocol == IPPROTO_UDP) ? 2 : 0;
    int src_port = 0;
    if (protocol == 1) { // TCP
        const struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ihl * 4));
        src_port = ntohs(tcp_header->source);
    } else if (protocol == 2) { // UDP
        const struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ihl * 4));
        src_port = ntohs(udp_header->source);
    }

    // Проверяем правила
    if (shouldBlockPacket(ip_header, src_port, protocol)) {
        std::cout << "[BLOCKED] Source IP: " << source_ip << ", Port: " << src_port << std::endl;
        return;
    }

    // ��азрешенный пакет
    std::cout << "[ALLOWED] Source IP: " << source_ip << ", Port: " << src_port << std::endl;
}

// Поток для управления правилами
void consoleThread() {
    while (running) {
        std::cout << "Введите команду (add = добавить правило, exit = выход): ";
        std::string command;
        std::cin >> command;

        if (command == "add") {
            addRule();
        } else if (command == "exit") {
            running = false;
            break;
        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    const char* device = "eth0";

    // Загружаем правила из файла
    loadRulesFromFile();

    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << device << ": " << errbuf << std::endl;
        return 1;
    }

    std::cout << "[INFO] Starting packet capture on device: " << device << std::endl;

    std::thread dos_thread(resetDoSCounters);
    std::thread console_thread(consoleThread);

    // Основной цикл захвата пакетов
    pcap_loop(handle, 0, packetHandler, nullptr);

    // Завершение потоков
    running = false;
    dos_thread.join();
    console_thread.join();
    pcap_close(handle);

    return 0;
}

