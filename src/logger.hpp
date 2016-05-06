#ifndef LOGGER_H
#define LOGGER_H

#include "config.h"

#include <string>
#include <sstream>
#include <memory>
#include <queue>
#include <iostream>
#include <iomanip>
#include <syslog.h>

#define BOOST_LOG_TRIVIAL(level) Logger("["#level"]")

class Logger {
	private:
		class Data {
			public:
				Data(std::string const &level) : level(level) {}
				bool completed = false;
				std::string const level;
				std::time_t t = std::time(nullptr);
				std::ostringstream ss;
		};

	public:
		Logger(std::string const &level) {
			data.reset(new Data(level));
			q.push(data);
		}

		~Logger() {
			data->completed = true;
			while (!q.empty()) {
				auto &n = q.front();
				if (!n->completed) break;
				if (use_syslog) {
					::syslog(LOG_INFO, "%s", n->ss.str().c_str());
				} else {
					auto t = std::localtime(&n->t);
					char s[200];
					::snprintf(s, sizeof(s), "%02d-%02d-%02d %02d/%02d/%02d %+04d", t->tm_year % 100, t->tm_mon, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec, t->tm_isdst);
					std::cerr << s << ' ' << n->level << ' ' << n->ss.str() << std::endl;
				}
				q.pop();
			}
		}

		template<typename Arg>
		Logger& operator<<(Arg && arg) {
			data->ss << std::forward<Arg>(arg);
			return *this;
		}

		static bool use_syslog;

	private:
		static std::queue<std::shared_ptr<Data>> q;
		std::shared_ptr<Data> data;
};

#endif /* end of include guard: LOGGER_H */
