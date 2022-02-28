#include <signal.h>

#include <iostream>
#include <vector>
#include "BPF.h"
#include "bcc_common.h"
#include "common.h"
#include "libbpf.h"
#include "perf_reader.h"

const std::string BPF_PROGRAM = R"(
#include <linux/ptrace.h>

struct info_t {
  char name[64];
  __u64 sz;
};
BPF_PERF_OUTPUT(events);

KFUNC_PROBE(__x64_sys_write, struct pt_regs *regs)
{

  struct info_t info = {};
  //bpf_probe_read_kernel(info.name, sizeof(info.name), (char*)PT_REGS_PARM2(regs));
  info.sz = PT_REGS_PARM3(regs);
  if(info.sz > 64){
    info.sz = 64;
  }

  bpf_probe_read_user_str(&info.name, info.sz, (void *)PT_REGS_PARM2(regs));

  if(info.name[0] == 'a' && info.name[1] == 'b'){
    // bpf_trace_printk("buf: %s size: %ld\n", info.name, info.sz);
    events.perf_submit(ctx, &info, sizeof(info));
  }
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

void handle_output(void *cb_cookie, void *data, int data_size) {
  // std::cout << "Hello Perf output!!" << std::endl;
  // dump(data, data_size);
}

void handle_lost(void *cb_cookie, uint64_t lost) {
  std::cout << "Lost!! - " << lost << std::endl;
}

void signalHandler(int signum) {
  std::cout << "Interrupt signal (" << signum << ") received.\n";

  // cleanup and close up stuff here
  // terminate program

  exit(signum);
}

int main(int argc, char const *argv[]) {
  signal(SIGINT, signalHandler);

  ebpf::BPF bpf;
  auto res = bpf.init(BPF_PROGRAM);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int prog_fd;
  res = bpf.load_func("kfunc____x64_sys_write", BPF_PROG_TYPE_TRACING, prog_fd);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int ret = bpf_attach_kfunc(prog_fd);
  if (ret < 0) {
    std::cerr << "bpf_attach_kfunc failed: " << ret << std::endl;
    return 1;
  }

  auto cpus = ebpf::get_online_cpus();
  std::vector<perf_reader *> readers;
  for (auto i : cpus) {
    // see https://man7.org/linux/man-pages/man2/perf_event_open.2.html
    auto reader = static_cast<perf_reader *>(
        bpf_open_perf_buffer(&handle_output, &handle_lost, nullptr, -1, i,
                             DEFAULT_PERF_BUFFER_PAGE_CNT));
    int reader_fd = perf_reader_fd(reader);
    auto table = bpf.get_table("events");

    bpf_update_elem(table.get_fd(), &i, &reader_fd, 0);
    readers.push_back(reader);
  }

  std::cout << "Started tracing, hit Ctrl-C to terminate." << std::endl;
  while (true) {
    perf_reader_poll(readers.size(), readers.data(), 500);
  }

  return 0;
}
