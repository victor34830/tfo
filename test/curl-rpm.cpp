#include <fstream>
#include <iostream>
#include <vector>
#include <map>

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <sys/random.h>
#include <time.h>

/* somewhat unix-specific */
#include <sys/time.h>
#include <unistd.h>
#include <inttypes.h>

/* curl stuff */
#include <curl/curl.h>
using namespace std;

vector<string> mirrors;



// Should start from:
static string mirror_master = "https://admin.fedoraproject.org/mirrormanager/";

// or from (see /etc/yum.repos.d/fedora-updates.repo):
// https://mirrors.fedoraproject.org/metalink?repo=updates-released-f37&arch=x86_64&country=gb"
// See https://fedoraproject.org/wiki/Infrastructure/MirrorManager

static string mirrorslist = "https://admin.fedoraproject.org/mirrormanager/mirrors/Fedora/37/x86_64";

static const char *subdir = "/updates/37/Everything";

static vector<string> directories;
static vector<string> rpms;

#define RATE_SECS	10

static uint64_t cur_count;
static uint64_t secs_count[RATE_SECS];
static uint64_t total_count;
static unsigned num_samples;
static time_t last_time;

static unsigned files_completed;
static uint64_t bytes_received;

bool output_details;

class rpm {
public:
	string& mirror;
	string& file;
	ofstream fs_rx;
	time_t start_time;
	unsigned num_bytes;

	rpm(string& mirror, string &file, time_t start_time, bool save_file) :
		mirror(mirror), file(file), start_time(start_time), num_bytes(0) {
		if (save_file)
			fs_rx.open("/tmp/"s + file, ios_base::out);
	}
};

static map<CURL *, class rpm *> rpm_get;

class rpm_list {
public:
	string& mirror;
	string& dir;
	ofstream fs_rx;
	unsigned num_rpm;
	string remainder;

	rpm_list(string& mirror, string &dir) :
		mirror(mirror), dir(dir), num_rpm(0), remainder("")  {
		fs_rx.open("/tmp"s + dir + ".html"s, ios_base::out);
	}
};

static map<CURL *, class rpm_list *> rpm_list_get;

static void
get_easy_file(string &file, size_t (*rx_func)(void *, size_t, size_t, void *))
{
	int res;
	CURL *curl = curl_easy_init();

	curl_easy_setopt(curl, CURLOPT_URL, file.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, rx_func);

	res = curl_easy_perform(curl);
	if (res)
		cerr << "curl_easy_perform returned " << res << "\n";

	curl_easy_cleanup(curl);
}

static size_t
rpm_rx_func(void *data, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	class rpm *rpm = rpm_get[userp];
	time_t now_time;
	unsigned i;
	unsigned rate_secs;
	unsigned rate_frac;
	unsigned div;

	rpm->num_bytes += realsize;
	if (rpm->fs_rx.is_open())
		rpm->fs_rx.write(reinterpret_cast<char *>(data), realsize);

	now_time = time(NULL);
	if (now_time != last_time) {
		total_count = total_count - secs_count[last_time % RATE_SECS] + cur_count;
		secs_count[last_time % RATE_SECS] = cur_count;
		cur_count = 0;

		for (i = (last_time + 1) % RATE_SECS; i != now_time % RATE_SECS; i++) {
			total_count -= secs_count[i % RATE_SECS];
			secs_count[i % RATE_SECS] = 0;
		}

		last_time = now_time;
		num_samples++;

		div = num_samples >= RATE_SECS + 2 ? RATE_SECS : num_samples;
		rate_secs = (total_count + div / 2) / div;
		rate_frac = (rate_secs / 10000) % 100;
		cout << rate_secs / 1000000 << "." << (rate_frac < 10 ? "0" : "") << rate_frac << "Mb/s - completed " << files_completed << "\n";
	}

	cur_count += realsize;
	bytes_received += realsize;

	return realsize;
}

static void
open_file(CURLM *multi_handle, string &rpm_name, time_t start_time, bool write_file)
{
	string& source = mirrors[random() % mirrors.size()];
	CURL *handle;
	string url;

	handle = curl_easy_init();

	url = source + subdir + "/x86_64/Packages/" + char(tolower(rpm_name[0])) + "/" + rpm_name;

	rpm_get[handle] = new rpm(source, rpm_name, start_time, write_file);

	curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, reinterpret_cast<void *>(handle));
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, rpm_rx_func);
	curl_easy_setopt(handle, CURLOPT_TIMEOUT, 60L);
	curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1L);

	curl_multi_add_handle(multi_handle, handle);

	if (output_details)
		cout << "Getting " << url << "\n";
}

static void
open_file(CURLM *multi_handle, time_t start_time, bool write_file)
{
	open_file(multi_handle, rpms[random() % rpms.size()], start_time, write_file);
}

int get_rpms(unsigned num_files, unsigned num_concurrent, bool save_files)
{
	CURLM *multi_handle;
	unsigned rate;
	int still_running = 1; /* keep number of running handles */
	int last_still_running;
	int i;
	unsigned started_files = 0;
	CURLMsg *msg; /* for picking up messages with the transfer status */
	int msgs_left; /* how many messages are left */
	time_t cur_time;
	unsigned rate_frac;

	/* init a multi stack */
	multi_handle = curl_multi_init();

	cur_time = time(NULL);

	/* Allocate one CURL handle per transfer */
	for (i = 0; i < num_concurrent; i++)
		open_file(multi_handle, cur_time, save_files);

	started_files = num_concurrent;
	last_still_running = num_concurrent;

	while (still_running) {
		CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

		unsigned num_finished = last_still_running - still_running;
		if (num_finished)
			cur_time = time(NULL);
		for (i = 0; i < num_finished; i++) {
			while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
				if (msg->msg == CURLMSG_DONE) {
					class rpm *rpm = rpm_get[msg->easy_handle];

					if (rpm->fs_rx.is_open())
						rpm->fs_rx.close();

					if (msg->data.result == CURLE_HTTP_RETURNED_ERROR || rpm->num_bytes < 200) {
						if (output_details)
							cout << rpm->file << " from " << rpm->mirror << " completed result " << msg->data.result << " with " << rpm->num_bytes << " bytes\n";

						open_file(multi_handle, rpm->file, cur_time, save_files);

						still_running++;
					} else {
						if (output_details) {
							rate = cur_time != rpm->start_time ? rpm->num_bytes / (cur_time - rpm->start_time) : rpm->num_bytes;
							rate_frac = (rate / 10000) % 100;
							cout << "Transfer of " << rpm->file << " from " << rpm->mirror <<
								" completed with status " << msg->data.result << ", size " <<
								 rpm->num_bytes <<  " " << rate / 1000000 << "." <<
//								 format("{:<02}", rate / 1000000, (rate / 10000) % 100)
								 (rate_frac < 10 ? "0" : "") << rate_frac
								 << " Mb/s\n";
						}

						if (started_files < num_files) {
							open_file(multi_handle, cur_time, save_files);
							still_running++;
							started_files++;
						}

						files_completed++;
					}

					curl_multi_remove_handle(multi_handle, msg->easy_handle);
					curl_easy_cleanup(msg->easy_handle);

					rpm_get.erase(msg->easy_handle);
					delete rpm;
				} else {
					class rpm *rpm = rpm_get[msg->easy_handle];
					cout << rpm->file << " returned " << msg->msg << "\n";
				}
			}
			last_still_running = still_running;
		}

		if (still_running)
			/* wait for activity, timeout or "nothing" */
			mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);

		if (mc)
			break;
	}

	curl_multi_cleanup(multi_handle);

	return 0;
}

// <tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="k3b-22.08.3-2.fc37.x86_64.rpm">k3b-22.08.3-2.fc37.x86_64.rpm</a></td><td align="right">2022-11-25 21:35  </td><td align="right"> 10M</td><td>&nbsp;</td></tr>
// <tr><td class="link"><a href="AMF-devel-1.4.26-1.fc37.noarch.rpm" title="AMF-devel-1.4.26-1.fc37.noarch.rpm">AMF-devel-1.4.26-1.fc37.noarch.rpm</a></td><td class="size">            3383265</td><td class="date">2022-Oct-09 19:57</td></tr>
// <a href="bacula-client-13.0.1-4.fc37.x86_64.rpm">bacula-client-13.0.1-4.fc37.x86_64.rpm</a>             29-Nov-2022 13:24    232K
// <li><a href="e-antic-1.3.0-1.fc37.i686.rpm"> e-antic-1.3.0-1.fc37.i686.rpm</a></li>
// <a href="tacacs-F4.0.4.28.7fb~20220905g25fd8f0-1.fc37.x86_64.rpm">tacacs-F4.0.4.28.7fb~20220905g25fd8f0-1.fc37.x8..&gt;</a> 11-Oct-2022 15:48              123732
/* <tr>
<td class="f11"><div class="name"><a href="ucrt64-gcc-12.2.1-4.fc37.x86_64.rpm" title="ucrt64-gcc-12.2.1-4.fc37.x86_64.rpm">ucrt64-gcc-12.2.1-4.fc37.x86_64.rpm</a></div></td>
<td><div class="size" title="24604218 bytes">23.46 MB</div></td>
<td><div class="mtime">2022-11-15 18:08:40 </div></td>
</tr>
*/
// <tr><td><a href="v8-devel-10.2.154.15-1.18.12.1.1.fc37.x86_64.rpm" title="v8-devel-10.2.154.15-1.18.12.1.1.fc37.x86_64.rpm">v8-devel-10.2.154.15-1.18.12.1.1.fc37.x86_64.rpm</a></td><td>              15754</td><td>2022-Nov-07 15:26</td></tr>^M
// <tr><td valign="top"><img src="/icons/unknown.gif" alt="[   ]"></td><td><a href="yacreader-9.10.0-1.fc37.x86_64.rpm">yacreader-9.10.0-1.fc37.x86_64.rpm</a></td><td align="right">2022-10-30 17:09  </td><td align="right">1.5M</td><td>&nbsp;</td></tr>
// <li><a href="e-antic-1.3.0-1.fc37.i686.rpm"> e-antic-1.3.0-1.fc37.i686.rpm</a></li>
// <a href="Falcon-0.9.6.8-25.fc37.x86_64.rpm">Falcon-0.9.6.8-25.fc37.x86_64.rpm</a>                  27-Sep-2022 17:03             1849614
// <a href="NetworkManager-config-connectivity-fedora-1.40.6-1.fc37.noarch.rpm">NetworkManager-config-connectivity-fedora-1.40...&gt;</a> 30-Nov-2022 18:23     13K
// <tr><td class="link"><a href="pacemaker-cluster-libs-2.1.5-0.3.rc3.fc37.i686.rpm" title="pacemaker-cluster-libs-2.1.5-0.3.rc3.fc37.i686.rpm">pacemaker-cluster-libs-2.1.5-0.3.rc3.fc37.i686.rpm</a></td><td class="size">126.8 KiB</td><td class="date">2022-Nov-25 10:37</td></tr>^M

static unsigned
process_rpm_dir_line(string& line)
{
	string what = "<a href=\"";
	string rpm_end = ".rpm\"";
	size_t a_href, a_end, name_start, name_end;

	if ((a_href = line.find(what)) == string::npos)
		return 0;

	if ((a_end = line.find(rpm_end, a_href + what.length())) == string::npos)
		return 0;

	name_start = a_href + what.length();
	name_end = a_end + rpm_end.length() - 1;
	rpms.push_back(line.substr(name_start, name_end - name_start));

	return 1;
}

static void
get_rpm_list_file(void)
{
	fstream fs ("k.html", ios_base::in);
	string line;

	if (!fs)
		cerr << "Could not open k file\n";

	while (getline(fs, line))
		process_rpm_dir_line(line);
}

static size_t
rpm_dir_rx_func(void *data, size_t size, size_t nmemb, void *userp)
{
	string lines((char *)data, size * nmemb);
	size_t lend;
	string line;
	class rpm_list *rl = rpm_list_get[userp];

	rl->fs_rx.write(reinterpret_cast<char *>(data), size * nmemb);

	if (rl->remainder.length())
		lines.insert(0, rl->remainder);

	for (size_t nnl = lines.find("</tr><"); nnl != string::npos; nnl = lines.find("</tr><", nnl + 7))
		lines.insert(nnl + 5, "\n");

	while ((lend = lines.find('\n')) != string::npos) {
		line = lines.substr(0, lend + 1);
		rl->num_rpm += process_rpm_dir_line(line);
		lines.erase(0, lend + 1);
	}

	rl->remainder = lines;

	return size * nmemb;
}

static void
open_rpm_directory(CURLM *multi_handle, string& dir)
{
	CURL *handle;
	string& source = mirrors[random() % mirrors.size()];
	string url;

	handle = curl_easy_init();

	url = source + subdir + "/x86_64/Packages/" + dir + "/";

	rpm_list_get[handle] = new rpm_list(source, dir);

	curl_easy_setopt(handle, CURLOPT_URL, url.c_str());
	curl_easy_setopt(handle, CURLOPT_WRITEDATA, handle);
	curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, rpm_dir_rx_func);
	curl_easy_setopt(handle, CURLOPT_TIMEOUT, 30L);
	curl_easy_setopt(handle, CURLOPT_FAILONERROR, 1L);

	curl_multi_add_handle(multi_handle, handle);
}

static void
get_rpm_list(void)
{
	CURLM *multi_handle;
	int still_running = 1; /* keep number of running handles */
	CURLMsg *msg; /* for picking up messages with the transfer status */
	int msgs_left; /* how many messages are left */
	int last_still_running = 0;

	/* init a multi stack */
	multi_handle = curl_multi_init();

	/* Allocate one CURL handle per transfer */
	for (auto&& d : directories) {
		open_rpm_directory(multi_handle, d);

		last_still_running++;
	}

	while (still_running) {
		CURLMcode mc = curl_multi_perform(multi_handle, &still_running);

		unsigned num_finished = last_still_running - still_running;
		for (unsigned i = 0; i < num_finished; i++) {
			while ((msg = curl_multi_info_read(multi_handle, &msgs_left))) {
				if (msg->msg == CURLMSG_DONE) {
					class rpm_list *rl = rpm_list_get[msg->easy_handle];

					if (output_details)
						cout << rl->dir << " from " << rl->mirror << " completed result " << msg->data.result << " with " << rl->num_rpm << " rpms\n";
					rl->fs_rx.close();

					if (msg->data.result == CURLE_HTTP_RETURNED_ERROR || !rl->num_rpm) {
						open_rpm_directory(multi_handle, rl->dir);

						still_running++;
					}

					curl_multi_remove_handle(multi_handle, msg->easy_handle);
					curl_easy_cleanup(msg->easy_handle);
					rpm_list_get.erase(msg->easy_handle);
					delete rl;
				} else {
					class rpm_list *rl = rpm_list_get[msg->easy_handle];
					cout << rl->dir << " returned " << msg->msg << "\n";
				}
			}
		}

		/* wait for activity, timeout or "nothing" */
		mc = curl_multi_poll(multi_handle, NULL, 0, 1000, NULL);

		if (mc)
			break;

		last_still_running = still_running;
	}

	curl_multi_cleanup(multi_handle);
}

static void
process_directories_line(string& line)
{
	if (line.find("\"[DIR]\"") == string::npos)
		return;

	line.erase(0, line.find("<a href=\"") + "<a href=\""s.length());
	line.erase(line.find_first_of("/"));
	directories.push_back(line);
}

static void
get_directories_file(void)
{
	// <tr><td valign="top"><img src="/icons/folder.gif" alt="[DIR]"></td><td><a href="4/">4/</a></td><td align="right">2022-12-17 01:20  </td><td align="right">  - </td><td>&nbsp;</td></tr>
	fstream fs ("directories.html", ios_base::in);
	string line;

	if (!fs)
		cerr << "Could not open directory file\n";

	while (getline(fs, line))
		process_directories_line(line);

	fs.close();
}

static string dirs_remainder;
static size_t
directory_rx_func(void *data, size_t size, size_t nmemb, void *userp)
{
	string lines((char *)data, size * nmemb);
	size_t lend;
	string line;

	if (dirs_remainder.length())
		lines.insert(0, dirs_remainder);

	while ((lend = lines.find('\n')) != string::npos) {
		line = lines.substr(0, lend + 1);
		process_directories_line(line);
		lines.erase(0, lend + 1);
	}

	dirs_remainder = lines;

	return size * nmemb;
}

static void
get_directories(void)
{
	string& source = mirrors[random() % mirrors.size()];
	string url = source + subdir + "/x86_64/Packages/";

	get_easy_file(url, directory_rx_func);
}


static bool in_fedora = false;

static void
process_mirrors_line(string& line)
{
	static string best_url;

	if (line.find_first_not_of(' ') == string::npos)
		return;

	if (in_fedora) {
		if (line.contains("<br />")) {
			if (!best_url.empty() &&
			    best_url.find("mirrors.n-ix.net/fedora/linux") == string::npos) {
				best_url.erase(0, best_url.find_first_of('"') + 1);
				best_url.erase(best_url.find_first_of('"'), string::npos);
				mirrors.push_back(best_url);
			}
			best_url.erase();
			in_fedora = false;
			return;
		}

		if (line.find("https://") != string::npos)
			best_url = line.substr(line.find_first_not_of(' '));
		else if (best_url.empty() && line.contains("http://"))
			best_url = line.substr(line.find_first_not_of(' '));
	}

	if (line.contains("Fedora Linux"))
		in_fedora = true;
}

static void
get_mirrors_file(void)
{
	fstream fs;
	string line;

	fs.open("mirrors.html", ios_base::in);
	if (!fs)
		cerr << "Could not open mirrors.html\n";

	while (getline(fs, line))
		process_mirrors_line(line);

	fs.close();
}

static string mirror_remainder;
static size_t
mirror_rx_func(void *data, size_t size, size_t nmemb, void *userp)
{
	string lines((char *)data, size * nmemb);
	size_t lend;
	string line;

	if (mirror_remainder.length())
		lines.insert(0, mirror_remainder);

	while ((lend = lines.find('\n')) != string::npos) {
		line = lines.substr(0, lend + 1);
		process_mirrors_line(line);
		lines.erase(0, lend + 1);
	}

	mirror_remainder = lines;

	return size * nmemb;
}

static void
get_mirrors(void)
{
	get_easy_file(mirrorslist, mirror_rx_func);
}

static void
help(const char *name)
{
	cout << name << ":\n";
	cout << "\t-h\tprint this\n";
	cout << "\t-m\tuse file for mirrors\n";
	cout << "\t-d\tuse file for directories\n";
	cout << "\t-r\tuse file for rpm names\n";
	cout << "\t-n num\tnumber of files to download\n";
	cout << "\t-c num\tnumber of concurrent downloads\n";
	cout << "\t-s\tsave downloaded files\n";
	cout << "\t-o\toutput details\n";
}

int
main(int argc, char **argv)
{
	int ch;
	bool mirrors_file = false;
	bool directories_file = false;
	bool rpms_file = false;
	unsigned seed;
	unsigned num_concurrent= 3;
	unsigned num_files = 10;
	bool save_files = false;
	time_t start_time, end_time;

	while ((ch = getopt(argc, argv, ":hmdrc:n:so")) != -1) {
		switch(ch) {
		case 'h':
			help(argv[0]);
			exit(0);
		case 'm':
			mirrors_file = !mirrors_file;
			break;
		case 'd':
			directories_file = !directories_file;
			break;
		case 'r':
			rpms_file = !rpms_file;
			break;
		case 'c':
			num_concurrent = atoi(optarg);
			break;
		case 'n':
			num_files = atoi(optarg);
			break;
		case 's':
			save_files = !save_files;
			break;
		case 'o':
			output_details = !output_details;
			break;
		case ':':
			cerr << ": error\n";
			break;
		case '?':
			cerr << "? error\n";
			break;
		default:
			cerr << (char)ch << " error\n";
			break;
		}
	}

	getrandom(&seed, sizeof(seed), 0);
	srandom(seed);

	if (mirrors_file)
		get_mirrors_file();
	else
		get_mirrors();

	if (output_details)
		for (auto&& m : mirrors) cout << m << "\n";
	cout << "Have " << mirrors.size() << " mirrors\n";

	if (directories_file)
		get_directories_file();
	else {
		while (!directories.size())
			get_directories();
	}

	if (output_details)
		for (auto&& d : directories) cout << d << "\n";
	cout << "Have " << directories.size() << " directories\n";

	if (rpms_file)
		get_rpm_list_file();
	else
		get_rpm_list();

	if (output_details)
		for (auto&& r : rpms) cout << r << "\n";
	cout << "Have " << rpms.size() << " rpms\n";

	start_time = time(NULL);
	get_rpms(num_files, num_concurrent, save_files);
	end_time = time(NULL);

	cout << "Received " << files_completed << " files in " << end_time - start_time << " seconds, " << bytes_received / (end_time - start_time) / 1000000.0 << " MB/s\n";
}
