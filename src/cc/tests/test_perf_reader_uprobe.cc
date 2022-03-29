#include <signal.h>
#include <time.h>

#include <iostream>
#include <vector>

#include "BPF.h"
#include "bcc_common.h"
#include "common.h"
#include "libbpf.h"
#include "perf_reader.h"
#include <unistd.h>

const std::string BPF_PROGRAM = R"(
#include <linux/sched.h>
#include <uapi/linux/ptrace.h>

//#define FROM_STACK

BPF_PERF_OUTPUT(events);
#ifndef FROM_STACK
#define MAX_OUT 2048
struct event_t
{
	char msg[MAX_OUT];
	u64 size;
};
BPF_PERCPU_ARRAY(events_heap, struct event_t, 1);
#endif

struct buffer {
    char data[80];
    u64 sz;
};

int do_entry(struct pt_regs *ctx) {

#ifdef FROM_STACK
    struct buffer buf={};
    buf.sz = PT_REGS_PARM2(ctx);
    if(buf.sz > 80){
        buf.sz = 80;
    }
    //bpf_probe_read_user(&buf.data, buf.sz, (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read_user_str(&buf.data, buf.sz, (void *)PT_REGS_PARM1(ctx));
    events.perf_submit(ctx,&buf,sizeof(buf));
#else
	int entry = 0;
	struct event_t* event = events_heap.lookup(&entry);
    // NOTE: event must be checked even if it will always be there.
	if(!event)
	{
		return 1;
	}
	event->size = sizeof(event->msg);
	bpf_probe_read_user(&event->msg, sizeof(event->msg), (const void*)(ctx->sp));
	events.perf_submit(ctx, event, sizeof(*event));
#endif
    return 0;
}
)";

void dump(const void *mem, unsigned int n) {
  const char *p = reinterpret_cast<const char *>(mem);
  for (unsigned int i = 0; i < n; i++) {
    std::cout << std::hex << int(p[i]) << " ";
  }
  std::cout << std::endl;
}

unsigned long counter = 1;
unsigned long total_bytes = 0;
unsigned long total_bytes_lost = 0;
unsigned long usleep_time = 100;

void increment(int data_size) {
  ++counter;
  total_bytes += data_size;
}

void handle_output(void *cb_cookie, void *data, int data_size) {
  // std::cout << "Hello Perf output!!" << std::endl;
  increment(data_size);
  usleep(usleep_time);
  // dump(data, data_size);
}

void handle_lost(void *cb_cookie, uint64_t lost) {
  total_bytes_lost += lost;
}

void signalHandler(int signum) {
  std::cout << "Interrupt signal (" << signum << ") received.\n";

  // cleanup and close up stuff here
  // terminate program

  exit(signum);
}

int main(int argc, char const *argv[]) {
  signal(SIGINT, signalHandler);

  std::string exec_path(argv[1]);
  pid_t pid = atoi(argv[2]);
  usleep_time = atoi(argv[3]);

  std::cout << "exec path: " << exec_path.c_str() << "\tpid: " << pid
            << std::endl;

  ebpf::BPF bpf;
  auto res = bpf.init(BPF_PROGRAM);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int prog_fd;
  res = bpf.load_func("do_entry", BPF_PROG_TYPE_KPROBE, prog_fd);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  auto ret = bpf.attach_uprobe(exec_path, "hook", "do_entry", 0L,
                               BPF_PROBE_ENTRY, pid);
  if (!ret.ok()) {
    std::cerr << "bpf_attach_kfunc failed: " << ret.code() << std::endl;
    return 1;
  }

  auto cpus = ebpf::get_online_cpus();
  std::vector<perf_reader *> readers;
  for (auto i : cpus) {
    auto reader = static_cast<perf_reader *>(
        bpf_open_perf_buffer(&handle_output, &handle_lost, nullptr, -1, i,
                             512 * DEFAULT_PERF_BUFFER_PAGE_CNT));
    int reader_fd = perf_reader_fd(reader);
    auto table = bpf.get_table("events");

    bpf_update_elem(table.get_fd(), &i, &reader_fd, 0);
    readers.push_back(reader);
  }

  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  time_t rawtime, curtime;

  time(&rawtime);
  while (true) {
    perf_reader_poll(readers.size(), readers.data(), -1);
    curtime = time(NULL);
    if (curtime >= rawtime + 1) {
      printf("count: %lu --- size: %lu --- lost: %lu --- Current local time and date: %s",
             counter, total_bytes / counter, total_bytes_lost, asctime(localtime(&curtime)));
      rawtime = curtime;
      counter = 1;
      total_bytes = 0;
      total_bytes_lost = 0;
    }
  }

  return 0;
}
