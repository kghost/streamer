#include "config.h"

#include <memory>
#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/log/trivial.hpp>

#include "error-code.hpp"

namespace po = boost::program_options;
namespace fs = boost::filesystem;

size_t const file_max_rotate = 10;
size_t const file_max_size = 10*1024*1024;

class port : public std::enable_shared_from_this<port> {
	public:
		port(boost::asio::io_service &io_service, fs::path &&working) : socket(io_service), working(working) {}

		void start(boost::asio::ip::udp::endpoint endpoint) {
			try {
				if (!fs::exists(working)) {
					gh::error_code ec;
					if (!fs::create_directories(working, ec)) {
						BOOST_LOG_TRIVIAL(error) << "Directory create error for endpoint " << endpoint << " at " << working << ": " << ec.message();
						return;
					}
				} else if (!fs::is_directory(working)) {
					BOOST_LOG_TRIVIAL(error) << "Directory already exists for endpoint: " << endpoint << " at " << working;
					return;
				}
			} catch (const gh::system_error &e) {
				BOOST_LOG_TRIVIAL(error) << "Error setup directory " << working << " for endpoint " << endpoint << ": " << e.what();
				return;
			}

			try {
				socket.open(endpoint.protocol());
				socket.bind(endpoint);
			} catch (const gh::system_error &e) {
				BOOST_LOG_TRIVIAL(error) << "endpiont " << endpoint << " start failed: " << e.what();
				return;
			}
			loop();
		}

	private:
		struct pcap_hdr {
			uint32_t magic_number;   /* magic number */
			uint16_t version_major;  /* major version number */
			uint16_t version_minor;  /* minor version number */
			int32_t thiszone;       /* GMT to local correction */
			uint32_t sigfigs;        /* accuracy of timestamps */
			uint32_t snaplen;        /* max length of captured packets, in octets */
			uint32_t network;        /* data link type */
		};

		struct pcaprec_hdr {
			uint32_t ts_sec;         /* timestamp seconds */
			uint32_t ts_usec;        /* timestamp microseconds */
			uint32_t incl_len;       /* number of octets of packet saved in file */
			uint32_t orig_len;       /* actual length of packet */
		};

		struct iphdr {
			uint8_t  version;
			uint8_t  tos;
			uint16_t tot_len;
			uint16_t id;
			uint16_t frag_off;
			uint8_t  ttl;
			uint8_t  protocol;
			uint16_t check;
			uint32_t saddr;
			uint32_t daddr;
		};

		struct udphdr {
			uint16_t source;
			uint16_t dest;
			uint16_t len;
			uint16_t check;
		};

		struct entry {
			struct pcaprec_hdr pcaprec_hdr;
			struct iphdr iphdr;
			struct udphdr udphdr;
		};

		std::shared_ptr<fs::ofstream> rotate(boost::asio::ip::udp::endpoint peer) {
			auto prefix = fs::path(working) /= boost::lexical_cast<std::string>(peer) += ".";
			gh::error_code ec;
			auto file = fs::path(prefix) += boost::lexical_cast<std::string>(file_max_rotate);
			if (fs::exists(file)) {
				fs::remove(file, ec);
				if (!ec) BOOST_LOG_TRIVIAL(warning) << "Rotate delete file " << file << " failed: " << ec.message();
			}
			for (size_t n = file_max_rotate - 1; n > 0; --n) {
				auto oldf = fs::path(prefix) += boost::lexical_cast<std::string>(n);
				if (fs::exists(oldf)) {
					fs::rename(oldf, fs::path(prefix) += boost::lexical_cast<std::string>(n+1), ec);
					if (!ec) BOOST_LOG_TRIVIAL(warning) << "Rotate rename file " << oldf << " failed: " << ec.message();
				}
			}
			auto fp = std::make_shared<fs::ofstream>();
			fp->open(prefix += "1", std::ios_base::trunc);
			pcap_hdr hdr { 0xd4c3b2a1, ntohs(2), ntohs(4), 0, 0, ntohl(65535), ntohl(228) /* LINKTYPE_IPV4 */ };
			fp->write(reinterpret_cast<char*>(&hdr), sizeof(hdr));
			return fp;
		}

		void loop() {
			auto me = shared_from_this();
			auto peer = std::make_shared<boost::asio::ip::udp::endpoint>();
			auto p = std::make_shared<std::array<char, 2048>>();
			socket.async_receive_from(boost::asio::mutable_buffers_1(p.get(), p->size()), *peer,
				[me, p, peer](const gh::error_code& ec, std::size_t bytes_transferred) {
					if (!ec) {
						std::shared_ptr<fs::ofstream> fp;
						auto it = me->files.lower_bound(*peer);
						if (it == me->files.end() || it->first != *peer) {
							fp = me->rotate(*peer);
							me->files.insert(it, decltype(me->files)::value_type(*peer, fp));
						} else {
							fp = it->second;
							if (size_t(fp->tellp()) + sizeof(pcap_hdr) + bytes_transferred > file_max_size) {
								fp = me->rotate(*peer);
								me->files.insert(it, decltype(me->files)::value_type(*peer, fp));
							}
						}
						struct timeval tv;
						::gettimeofday(&tv, nullptr);
						entry e = {
							{ ntohl(tv.tv_sec), ntohl(tv.tv_usec), ntohl(sizeof(iphdr) + sizeof(udphdr) + bytes_transferred), ntohl(sizeof(iphdr) + sizeof(udphdr) + bytes_transferred) },
							{ 0x45, 0, 0, 0, 0, 0, 17, 0, ntohl(me->socket.local_endpoint().address().to_v4().to_ulong()), ntohl(peer->address().to_v4().to_ulong()) },
							{ ntohs(me->socket.local_endpoint().port()), ntohs(peer->port()), ntohs(sizeof(udphdr) + bytes_transferred), 0 }
						};
						fp->write(reinterpret_cast<char*>(&e), sizeof(e));
						fp->write(p->begin(), bytes_transferred);
						fp->flush();
						me->loop();
					} else {
						BOOST_LOG_TRIVIAL(error) << "udp(" << me->socket.local_endpoint() << ") read error: " << ec.message();
					}
				});
		}

		boost::asio::ip::udp::socket socket;
		fs::path const working;
		std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<fs::ofstream>> files;
};

int main (int ac, char **av) {
	po::options_description desc("Options");
	desc.add_options()
	("help,h", "print this message")
	("directory,d", po::value<std::string>()->default_value("."), "destination directory (default: current directory)")
	("listen,l", po::value<std::vector<std::string> >()->composing(), "listening ports")
	;

	po::variables_map vm;
	try {
		po::store(po::command_line_parser(ac, av).options(desc).run(), vm);
		po::notify(vm);
	} catch (const po::error &ex) {
		std::cout << ex.what() << std::endl;
		return 1;
	}

	if (vm.count("help") || !vm.count("listen")) {
		std::cout << "Usage: " << av[0] << " startlua" << std::endl;
		std::cout << std::endl;
		std::cout << desc << std::endl;
		return 1;
	}

	fs::path const working(vm["directory"].as<std::string>());
	try {
		if (!fs::exists(working) || !fs::is_directory(working)) {
			std::cout << "can't open destination directory: " << working << std::endl;
			return 1;
		}
	} catch (const fs::filesystem_error& ex) {
		std::cout << ex.what() << std::endl;
		return 1;
	}

	boost::asio::io_service io_service;

	boost::asio::signal_set signals(io_service, SIGINT, SIGTERM);
	signals.async_wait([&io_service](const gh::error_code& ec, int signal_number) {
		if (!ec)
			io_service.stop();
	});

	auto resolver = std::make_shared<boost::asio::ip::udp::resolver>(io_service);
	for (auto &end : vm["listen"].as<std::vector<std::string>>()) {
		auto handler = [&io_service, &working, resolver, &end](const gh::error_code& ec, boost::asio::ip::udp::resolver::iterator iterator) {
			if (!ec) {
				for (decltype(iterator) iend; iterator != iend; ++iterator) {
					BOOST_LOG_TRIVIAL(info) << "Listining on port: " << iterator->endpoint() << " from " << end;
					std::make_shared<port>(io_service, std::move(fs::path(working) /= end))->start(iterator->endpoint());
				}
			} else {
				BOOST_LOG_TRIVIAL(error) << "Error resolve endpoint(" << end << "): " << ec.message();
			}
		};

		auto s = end.rfind(':');
		if (s == std::string::npos) {
			resolver->async_resolve({end}, handler);
		} else {
			resolver->async_resolve({end.substr(0, s), end.substr(s+1)}, handler);
		}
	}

	io_service.run();

	boost::log::core::get()->remove_all_sinks();

	return 0;
}
