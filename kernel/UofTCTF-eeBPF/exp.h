#include <errno.h>


/* Raw instruction */
#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)           \
    ((struct bpf_insn){                                 \
        .code    = CODE,                                \
        .dst_reg = DST,                                 \
        .src_reg = SRC,                                 \
        .off     = OFF,                                 \
        .imm     = IMM,                                 \
    })

/* Load 64-bit immediate (TWO instructions) */
#define BPF_LD_IMM64_RAW(DST, SRC, IMM)                  \
    ((struct bpf_insn){                                  \
        .code    = BPF_LD | BPF_DW | BPF_IMM,             \
        .dst_reg = DST,                                  \
        .src_reg = SRC,                                  \
        .off     = 0,                                    \
        .imm     = (uint32_t)(IMM),                       \
    }),                                                   \
    ((struct bpf_insn){                                  \
        .code    = 0,                                    \
        .dst_reg = 0,                                    \
        .src_reg = 0,                                    \
        .off     = 0,                                    \
        .imm     = (uint32_t)((uint64_t)(IMM) >> 32),     \
    })

#define BPF_LD_IMM64(DST, IMM) \
    BPF_LD_IMM64_RAW(DST, 0, IMM)

#define BPF_LD_MAP_FD(DST, MAP_FD) \
    BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)

/* Memory ops */
#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)                 \
    ((struct bpf_insn){                                  \
        .code    = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                                  \
        .src_reg = SRC,                                  \
        .off     = OFF,                                  \
        .imm     = 0,                                    \
    })

#define BPF_STX_MEM(SIZE, DST, SRC, OFF)                 \
    ((struct bpf_insn){                                  \
        .code    = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,    \
        .dst_reg = DST,                                  \
        .src_reg = SRC,                                  \
        .off     = OFF,                                  \
        .imm     = 0,                                    \
    })

/* Jumps */
#define BPF_JMP_IMM(OP, DST, IMM, OFF)                   \
    ((struct bpf_insn){                                  \
        .code    = BPF_JMP | BPF_OP(OP) | BPF_K,          \
        .dst_reg = DST,                                  \
        .src_reg = 0,                                    \
        .off     = OFF,                                  \
        .imm     = IMM,                                  \
    })

#define BPF_JMP32_IMM(OP, DST, IMM, OFF)                 \
    ((struct bpf_insn){                                  \
        .code    = BPF_JMP32 | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                                  \
        .src_reg = 0,                                    \
        .off     = OFF,                                  \
        .imm     = IMM,                                  \
    })

/* MOV */
#define BPF_MOV64_IMM(DST, IMM)                          \
    ((struct bpf_insn){                                  \
        .code    = BPF_ALU64 | BPF_MOV | BPF_K,           \
        .dst_reg = DST,                                  \
        .src_reg = 0,                                    \
        .off     = 0,                                    \
        .imm     = IMM,                                  \
    })

#define BPF_MOV64_REG(DST, SRC)                          \
    ((struct bpf_insn){                                  \
        .code    = BPF_ALU64 | BPF_MOV | BPF_X,           \
        .dst_reg = DST,                                  \
        .src_reg = SRC,                                  \
        .off     = 0,                                    \
        .imm     = 0,                                    \
    })

/* ALU */
#define BPF_ALU64_IMM(OP, DST, IMM)                      \
    ((struct bpf_insn){                                  \
        .code    = BPF_ALU64 | BPF_OP(OP) | BPF_K,        \
        .dst_reg = DST,                                  \
        .src_reg = 0,                                    \
        .off     = 0,                                    \
        .imm     = IMM,                                  \
    })

#define BPF_ALU64_REG(OP, DST, SRC)                      \
    ((struct bpf_insn){                                  \
        .code    = BPF_ALU64 | BPF_OP(OP) | BPF_X,        \
        .dst_reg = DST,                                  \
        .src_reg = SRC,                                  \
        .off     = 0,                                    \
        .imm     = 0,                                    \
    })

/* Exit */
#define BPF_EXIT_INSN()                                  \
    ((struct bpf_insn){                                  \
        .code    = BPF_JMP | BPF_EXIT,                    \
        .dst_reg = 0,                                    \
        .src_reg = 0,                                    \
        .off     = 0,                                    \
        .imm     = 0,                                    \
    })


    #define VERIFIER_LOG_SIZE 0x100000

    static int bpf(int cmd, union bpf_attr *attr, unsigned int size){
        return syscall(__NR_bpf, cmd, attr, size);
    }


    int create_map(void)
    {
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));
        
        attr.map_type = BPF_MAP_TYPE_ARRAY;
        attr.key_size = 4;
        attr.value_size = 8;
        attr.max_entries = 3;
        
        int fd = bpf_syscall(BPF_MAP_CREATE, &attr);
        printf("fd map %d \n", fd);
        if (fd < 0) {
            perror("BPF_MAP_CREATE");
            return -1;
        }
        return fd;
    }
    int update_map(int fd_m, uint64_t key , void* value, uint64_t flags){
        union bpf_attr attr;
        memset(&attr, 0, sizeof(attr));


        attr.map_fd = fd_m;
        attr.key    = (uint64_t)&key;
        attr.value  = (uint64_t)value;
        attr.flags = flags;
        
        int rc = bpf_syscall(BPF_MAP_UPDATE_ELEM , &attr);
        if (rc < 0) {
            perror("BPF_MAP_UPDATE");
            return -1;
        }
        return rc;
    }
    static int lookup_map(int map_fd, uint64_t key, void* outval){
        int ret = -1;

        union bpf_attr attr = {
            .map_fd = map_fd,
            .key = (uint64_t)&key,
            .value = (uint64_t)outval
        };

        ret = bpf(BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr));
        return ret;
    }
    
static int create_prog(struct bpf_insn insns[], uint64_t insn_cnt){

    char verifier_log_buff[VERIFIER_LOG_SIZE] = {0};

    int socks[2] = {0};

    int ret = -1;
    int prog_fd = -1;

    union bpf_attr attr = 
    {
        .prog_type = BPF_PROG_TYPE_SOCKET_FILTER,
        .insn_cnt = insn_cnt,
        .insns = (uint64_t)insns,
        .license = (uint64_t)"",
        .log_level = 2,
        .log_size = VERIFIER_LOG_SIZE,
        .log_buf = (uint64_t)verifier_log_buff
    };

    prog_fd = bpf_syscall(BPF_PROG_LOAD, &attr, sizeof(attr));

    if (prog_fd < 0){
        printf("[-] Program failed! Verifier log: %s\n", verifier_log_buff);
        printf("[-] Errno: %s\n", strerror(errno));
        goto done;
    } else {
        printf("[!] Exploit loaded! FD: %d\n", prog_fd);
        printf("[+] Setting up sockets\n");
    }

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socks) != 0){
        perror("[-] socketpair failed");
        goto done;
    }

    if (setsockopt(socks[0], SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(int)) != 0 ){
        perror("[-] setsockopt failed");
        goto done;
    }

    if (write(socks[1], "lokete", 6) != 6){
        perror("write");
        goto done;
    }

    // puts(verifier_log_buff);

done:
    close(socks[0]);
    close(socks[1]);

    return prog_fd;
}
    



    int bpf_syscall(enum bpf_cmd cmd, union bpf_attr *attr)
    {
        return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
    }