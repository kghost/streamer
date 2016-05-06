#include "logger.hpp"

bool Logger::use_syslog = false;
std::queue<std::shared_ptr<Logger::Data>> Logger::q;
