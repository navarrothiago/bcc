// #define CATCH_CONFIG_MAIN
#include <signal.h>

#include <iostream>
#include <vector>

#include "bcc_common.h"
#include "catch.hpp"
#include "common.h"
#include "libbpf.h"
#include "perf_reader.h"
#include "BPF.h"

// static const int DEFAULT_PERF_BUFFER_PAGE_CNT = 8;

// const std::string BPF_PROGRAM = R"(
// int on_sys_clone(void *ctx) {
//   bpf_trace_printk("Hello, World! Here I did a sys_clone call!\n");
//   return 0;
// }
// )";

const std::string BPF_PROGRAM = R"(
#include <linux/ptrace.h>

struct info_t {
  char name[64];
  int fd;
  int is_ret;
};
BPF_PERF_OUTPUT(events);

KFUNC_PROBE(__x64_sys_openat, struct pt_regs *regs)
{
  const char __user *filename = (char *)PT_REGS_PARM2(regs);
  struct info_t info = {};

  bpf_probe_read_user_str(info.name, sizeof(info.name), filename);
  info.is_ret = 0;
  events.perf_submit(ctx, &info, sizeof(info));
  return 0;
}

KRETFUNC_PROBE(__x64_sys_openat, struct pt_regs *regs, int ret)
{
  const char __user *filename = (char *)PT_REGS_PARM2(regs);
  struct info_t info = {};

  bpf_probe_read_user_str(info.name, sizeof(info.name), filename);
  info.fd = ret;
  info.is_ret = 1;
  events.perf_submit(ctx, &info, sizeof(info));
  return 0;
}
)";


void handle_output(void *cb_cookie, void *data, int data_size) {
  std::cout << "Hello Perf output!!" << std::endl;
}

void handle_lost(void *cb_cookie, uint64_t lost) {}

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
  res = bpf.load_func("kfunc____x64_sys_openat", BPF_PROG_TYPE_TRACING, prog_fd);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  int ret = bpf_attach_kfunc(prog_fd);
  if (ret < 0) {
    std::cerr << "bpf_attach_kfunc failed: " << ret << std::endl;
    return 1;
  }

  res = bpf.load_func("kretfunc____x64_sys_openat", BPF_PROG_TYPE_TRACING, prog_fd);
  if (!res.ok()) {
    std::cerr << res.msg() << std::endl;
    return 1;
  }

  ret = bpf_attach_kfunc(prog_fd);
  if (ret < 0) {
    std::cerr << "bpf_attach_kfunc failed: " << ret << std::endl;
    return 1;
  }

  auto cpus = ebpf::get_online_cpus();
  std::vector<perf_reader *> readers;
  for (auto i : cpus) {
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
  /* code */
  return 0;
}
