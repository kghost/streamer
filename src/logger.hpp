#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <sstream>
#include <memory>
#include <queue>
#include <iostream>
#include <iomanip>

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
			for (;;) {
				auto &n = q.front();
				if (!n->completed) break;
				std::cerr << std::put_time(std::localtime(&n->t), "%F %T ") << n->level << n->ss.str() << std::endl;
				q.pop();
			}
		}

		template<typename Arg>
		Logger& operator<<(Arg && arg) {
			data->ss << std::forward<Arg>(arg);
			return *this;
		}

	private:
		static std::queue<std::shared_ptr<Data>> q;
		std::shared_ptr<Data> data;
};

#endif /* end of include guard: LOGGER_H */
