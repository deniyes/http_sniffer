#include <stdio.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <string.h>
//#include <net/if.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/filter.h>
#include <getopt.h>
#include <pthread.h>
#include <stddef.h>
#include <ctype.h>
#include <linux/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>


char* sniffer_log_get_header(int offset, char *conf);
int sniffer_set_num(char *value, int offset, char *conf);
int sniffer_set_flg(char *value, int offset, char *conf);
int sniffer_set_path(char *value, int offset, char *conf);
int sniffer_set_hander_array(char *value, int offset, char *conf);


#define MAX_REQUEST_DATA_SIZE (2048)

typedef char* (*log_handler)(int offset, char* conf);
typedef struct log_output_s log_output_t;
struct log_output_s {
    char *name;
    int name_len;
    int offset;
    log_handler log_handler;
};


typedef struct {
    int thread_num;
    int max_thread_num;
    int daemon;
    char access_log[128];
    char error_log[128];
    char status_file[128];
    log_output_t *log_handlers[128];

} sniffer_conf_t;


sniffer_conf_t  g_sniffer_conf = {
    .thread_num = 1,
    .max_thread_num = 1,
    .daemon = 1,
    .access_log = "access.log",
    .error_log = "error.log",
    .status_file = "/etc/openvpn/openvpn-status.log",
    .log_handlers = {NULL},

};

char *g_request_method[] = {"GET ", "POST ", NULL};
char *g_response_method[]= {"HTTP/1.0 ", "HTTP/1.1 ", NULL};

typedef int (*Handler)(char *value, int offset, char *conf);
typedef struct{
    char *name;
    int len;
    void *conf;
    int offset;
    Handler handler;
} conf_name_mapping_t;


typedef struct packet_info_s {
    unsigned short s_port;
    unsigned short d_port;
    unsigned int s_addr;
    unsigned int d_addr;
}packet_info_t;


typedef struct request_info_s request_info_t;
struct request_info_s{
    time_t cur_time;
    int req_app_len;
    packet_info_t packet_info;
    
    char *token;
    char *src_ip;
    char *mid_ip;
    char *dst_ip;
    char *src_port;
    char *dst_port;
    char *time;

    char *uri;
    char *host;
    char *user_agent;
    char *referer;
    char *content_type;
    char *content_length;
    char *transfer_encoding;
    char *content_encoding;
    char *cookie;
    char *connection;
    char *response_status;
    char *accept_encoding;
    char *accept_charset;

    char *req_app_data;
    char *extra;
    char *cur;
    char *end;
    request_info_t *partern;
    request_info_t *hash_next;
    request_info_t *list_next;
    char request_data[MAX_REQUEST_DATA_SIZE];
};


conf_name_mapping_t name_mapping[] = {
    {"thread_num",
    10,
    &g_sniffer_conf,
    offsetof(sniffer_conf_t, thread_num),
    sniffer_set_num},
    {"max_thread_num",
    14,
    &g_sniffer_conf,
    offsetof(sniffer_conf_t, max_thread_num),
    sniffer_set_num},
    {"access_log",
    10,
    &g_sniffer_conf,
    offsetof(sniffer_conf_t, access_log),
    sniffer_set_path},
    {"error_log",
    9,
    &g_sniffer_conf,
    offsetof(sniffer_conf_t, error_log),
    sniffer_set_path},
    {"status_file",
    11,
    &g_sniffer_conf,
    offsetof(sniffer_conf_t, status_file),
    sniffer_set_path},
    {"daemon",
    6,
    &g_sniffer_conf,
    offsetof(sniffer_conf_t, daemon),
    sniffer_set_flg},
    {"access_log_format",
    17,
    &g_sniffer_conf,
    offsetof(sniffer_conf_t, log_handlers),
    sniffer_set_hander_array},
    {NULL,
     0,
     NULL,
     0,
     NULL}
};


log_output_t log_format[] = {
        {"Content-Type",
        12,
        offsetof(request_info_t, content_type),
        sniffer_log_get_header},
        {"Content-Length",
        14,
        offsetof(request_info_t, content_length),
        sniffer_log_get_header},
        {"Content-Encoding",
        16,
        offsetof(request_info_t, content_encoding),
        sniffer_log_get_header},
        {"Transfer-Encoding",
        17,
        offsetof(request_info_t, transfer_encoding),
        sniffer_log_get_header},
        {"Host",
        4,
        offsetof(request_info_t, host),
        sniffer_log_get_header},
        {"status",
        6,
        offsetof(request_info_t, response_status),
        sniffer_log_get_header},
        {"User-Agent",
        10,
        offsetof(request_info_t, user_agent),
        sniffer_log_get_header},     
        {"Accept-Encoding",
        15,
        offsetof(request_info_t, accept_encoding),
        sniffer_log_get_header},
        {"Referer",
        7,
        offsetof(request_info_t, referer),
        sniffer_log_get_header},
        {"time",
        4,
        offsetof(request_info_t, time),
        sniffer_log_get_header},
        {"uri",
        3,
        offsetof(request_info_t, uri),
        sniffer_log_get_header},
        {"Token",
        5,
        offsetof(request_info_t, token),
        sniffer_log_get_header},
        {"Source_IP",
        9,
        offsetof(request_info_t, src_ip),
        sniffer_log_get_header},
        {"Middle_IP",
        9,
        offsetof(request_info_t, mid_ip),
        sniffer_log_get_header},
        {"Destination_IP",
        14,
        offsetof(request_info_t, dst_ip),
        sniffer_log_get_header},
        {"Source_Port",
        11,
        offsetof(request_info_t, src_port),
        sniffer_log_get_header},
        {"Destination_Port",
        16,
        offsetof(request_info_t, dst_port),
        sniffer_log_get_header},
        {NULL,
        0,
        0,
        NULL}
};

#define max_request_num (4096)
#define max_request_hash (937)

#define g_request_item_timeout  (300)

typedef struct free_buf_s{
    int free_buf_num;
    request_info_t *free_buf_header;
    pthread_mutex_t lock;
    request_info_t request_buf[max_request_num];
    request_info_t *request_hash[max_request_hash];
    pthread_mutex_t lock_hash[max_request_hash];
}free_buf_t;

free_buf_t g_free_buf;

FILE *g_access_file = NULL;
FILE *g_error_file = NULL;


unsigned int 
sniffer_hash_function(packet_info_t *info)
{
    return (info->s_addr + info->d_addr + info->s_port + info->d_port) ;
}

int sniffer_compare_function (packet_info_t *src, packet_info_t *dst)
{
    return (src->s_addr == dst->s_addr \
        && src->d_addr == dst->d_addr \
        && src->s_port == dst->s_port \
        && src->d_port == dst->d_port);
}

int sniffer_compare_function_r (packet_info_t *src, packet_info_t *dst)
{
    return (src->s_addr == dst->d_addr \
        && src->d_addr == dst->s_addr \
        && src->s_port == dst->d_port \
        && src->d_port == dst->s_port);
}



char* sniffer_log_get_header(int offset, char *conf)
{
    char **p = (char**)(conf + offset);
    return (*p);
}


void init_g_free_buf()
{
    int i = 0;
    for (i = max_request_num - 2; i >= 0; i --) {
        memset(&g_free_buf.request_buf[i], 0, sizeof(request_info_t));        
        g_free_buf.request_buf[i].list_next = &g_free_buf.request_buf[i + 1];
    }
    for (i = 0; i < max_request_hash; i ++) {
        g_free_buf.request_hash[i] = NULL;
        pthread_mutex_init(&g_free_buf.lock_hash[i], NULL);
    }
    g_free_buf.free_buf_header = &g_free_buf.request_buf[0];
    g_free_buf.free_buf_num = max_request_num;
    pthread_mutex_init(&g_free_buf.lock, NULL);
}


request_info_t *get_free_request()
{
    request_info_t *p = NULL;
    pthread_mutex_lock(&g_free_buf.lock);
    if (g_free_buf.free_buf_num > 0) {
        p = g_free_buf.free_buf_header;
        g_free_buf.free_buf_header = g_free_buf.free_buf_header->list_next;
        g_free_buf.free_buf_num --;
        p->list_next = NULL;
    }
    pthread_mutex_unlock(&g_free_buf.lock);
    return p;
}

void sniffer_hash_del(request_info_t *item);

void release_request_info(request_info_t *r)
{
    if (r->extra) {
        free(r->extra);
        r->extra = NULL;
    }
    if (r->partern) {        
        sniffer_hash_del(r->partern);
        release_request_info(r->partern);
    }
    memset(r, 0, sizeof(request_info_t));
    pthread_mutex_lock(&g_free_buf.lock);
    r->list_next = g_free_buf.free_buf_header;
    g_free_buf.free_buf_header = r;
    g_free_buf.free_buf_num ++;
    pthread_mutex_unlock(&g_free_buf.lock);
}


void sniffer_hash_add(request_info_t *item)
{
    unsigned int hash_value = sniffer_hash_function(&item->packet_info);

    pthread_mutex_lock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
    request_info_t *head = g_free_buf.request_hash[hash_value % max_request_hash];
    request_info_t *p = head;
    while (p) {
        if (sniffer_compare_function(&item->packet_info, &p->packet_info)) {
            pthread_mutex_unlock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
            return;
        }
        p = p->hash_next;
    }
    fprintf(g_error_file, "src_ip:%s dst_ip:%s src_port: %s dst_port:%s is adding.\n", \
        item->src_ip, item->dst_ip, item->src_port, item->dst_port);
    item->hash_next = head;
    g_free_buf.request_hash[hash_value % max_request_hash] = item;
    pthread_mutex_unlock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
}

void sniffer_hash_mergh(request_info_t *item)
{
    unsigned int hash_value = sniffer_hash_function(&item->packet_info);

    pthread_mutex_lock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
    request_info_t *head = g_free_buf.request_hash[hash_value % max_request_hash];
    request_info_t *p = head;
    size_t start_offset = offsetof(request_info_t, uri);
    size_t end_offset = offsetof(request_info_t, accept_charset);
    char **pos = NULL;
    char **dst = NULL;
    while (p) {
        if (sniffer_compare_function_r(&item->packet_info, &p->packet_info)) {
            fprintf(g_error_file, "src_ip:%s dst_ip:%s  src_port: %s dst_port:%s is merghing.\n", \
                item->dst_ip, item->src_ip, item->dst_port, item->src_port);
            for(pos = (char**)((char*)p + start_offset), dst = (char**)((char*)item + start_offset); 
                pos <= (char**)((char*)p + end_offset), dst <= (char**)((char*)item + end_offset); pos ++)
                if (*pos != NULL && *dst == NULL)
                    *dst = *pos;
            
            pthread_mutex_unlock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
            return;
        }
        p = p->hash_next;
    }
    pthread_mutex_unlock(&g_free_buf.lock_hash[hash_value % max_request_hash]);

    fprintf(g_error_file, "src_ip:%s dst_ip:%s  src_port: %s dst_port:%s can't find partern item.\n", \
        item->dst_ip, item->src_ip, item->dst_port, item->src_port);
}


void sniffer_hash_del(request_info_t *item)
{
    unsigned int hash_value = sniffer_hash_function(&item->packet_info);

    pthread_mutex_lock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
    request_info_t *head = g_free_buf.request_hash[hash_value % max_request_hash];
    if (sniffer_compare_function(&head->packet_info, &item->packet_info)) {
        fprintf(g_error_file, "src_ip:%s dst_ip:%s  src_port: %s dst_port:%s is deleting.\n", \
                item->src_ip, item->dst_ip, item->src_port, item->dst_port);
        g_free_buf.request_hash[hash_value % max_request_hash] = head->hash_next;
        pthread_mutex_unlock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
        return;
    }
    
    request_info_t *p = head->hash_next;
    request_info_t *pre = head;
    while (p) {
        if (sniffer_compare_function(&item->packet_info, &p->packet_info)) {
            fprintf(g_error_file, "src_ip:%s dst_ip:%s  src_port: %s dst_port:%s is deleting.\n", \
                item->src_ip, item->dst_ip, item->src_port, item->dst_port);
            pre->hash_next = p->hash_next;
            pthread_mutex_unlock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
            return;
        }
        pre = p;
        p = p->hash_next;
    }
    pthread_mutex_unlock(&g_free_buf.lock_hash[hash_value % max_request_hash]);
    fprintf(g_error_file, "src_ip:%s dst_ip:%s  src_port: %s dst_port:%s can't find deleting item.\n", \
        item->src_ip, item->dst_ip, item->src_port, item->dst_port);
}


void *sniffer_hash_aging(void *unused) 
{
    int index = 0;
    time_t now = 0;
    request_info_t *head = NULL;
    request_info_t *pre = NULL;

    while (1) {
        for (index = 0; index < max_request_hash; index ++) {
            pthread_mutex_lock(&g_free_buf.lock_hash[index]);
            now = time(NULL);
            head = g_free_buf.request_hash[index];
            pre = g_free_buf.request_hash[index];
            while (head) {
                if (now - head->cur_time >= g_request_item_timeout) {
                    fprintf(g_error_file, "src_ip:%s dst_ip:%s  src_port: %s dst_port:%s will aging item.\n", \
                                                       head->src_ip, head->dst_ip, head->src_port, head->dst_port);
                    if (head == g_free_buf.request_hash[index])
                        g_free_buf.request_hash[index] = head->hash_next;
                    else
                        pre->hash_next = head->hash_next;
                    release_request_info(head);
                }
                pre = head;
                head = head->hash_next;
            }
            pthread_mutex_unlock(&g_free_buf.lock_hash[index]);
        }
        sleep(120);
    }
}


int sniffer_set_num(char *value, int offset, char *conf)
{
    int *t = (int*)((char*)conf + offset);

    char *s = value;
    int num = 0;
    while (*s != '\0') {
        if (isdigit(*s) == 0) {
             fprintf(g_error_file, "%c is not digit.\n", *s);
             return -1;
        }
        num = 10 * num + *s - '0';
        s ++;
    }
    *t = num;
    return 0;
 }


int sniffer_set_flg(char *value, int offset, char *conf)
{
    int *t = (int*)((char*)conf + offset);

    if (strncasecmp(value, "on", 2) == 0){
        *t = 1;
    } else if (strncasecmp(value, "off", 3) == 0){
        *t = 0;
    } else {
        fprintf(stderr, "unsupoort value for: %s\n", value);
        return -1;
    }
    return 0;
}

int sniffer_set_path(char *value, int offset, char *conf)
{
    char *p = conf + offset;

    strcpy(p, value);

    return 0;
}

enum decode_log_status {
    format_pre,
    format_start,
    item_start,
    item_stop,
    format_stop
};

void sniffer_push_hander(sniffer_conf_t *sniffer_conf, char *name, int name_len)
{
    int i = 0;
    log_output_t *log = &log_format[0];
    log_output_t **p = &sniffer_conf->log_handlers[0];

    while (log->name) {
        if (name_len != log->name_len) {
            log ++;
            continue;
        }
        if (strncasecmp(name, log->name, log->name_len) == 0) {
            while (*p)
                p ++;
            *p = log;
            break;
        }
        log ++;
    }
    if (!log->name) {
        fprintf(stderr, "unsupport log item.\n");
    }
}

int sniffer_set_hander_array(char *value, int offset, char *conf)
{
    sniffer_conf_t *sniffer_conf = (sniffer_conf_t*)conf;
    char *s = value;
    char *end = s + strlen(value);
    char *item = NULL;
    int len = 0;

    enum decode_log_status status;

    int i = 0;
    status = format_pre;

    while (s < end) {
        switch(status) {
            case format_pre:
                if (*s == '\"')
                    status = format_start;
                else if (*s != ' ' && *s != '\t')
                    goto ERROR;
                break;

            case format_start:
                if (*s == '$')
                    item = s + 1;
                    status = item_start;
                break;
            case item_start:
                if (*s == ' ' || *s == '\t') {
                    *s = '\0';
                    len = s - item;
                    if (len == 0)
                        goto ERROR;
                    sniffer_push_hander(sniffer_conf, item, len);
                    status = item_stop;
                }
                if (*s == '\"') {
                    *s = '\0';
                    len = s - item;
                    sniffer_push_hander(sniffer_conf, item, len);
                    status = format_stop;
                }
                break;
            case item_stop:
                if (*s == '$')
                    item = s + 1;
                    status = item_start;
                if (*s == '\"')
                    status = format_stop;
                break;
            case format_stop:
                break;

        }
        s ++;
    }
    return 0;
ERROR:
    fprintf(stderr, "unsupport log format: %s\n", value);
    return -1;
}


int parse_info(char *name, char *value)
{
    conf_name_mapping_t *p = &name_mapping[0];
    int len = strlen(name);
    while (p->name) {
        if (len != p->len) {
            p ++;
            continue;
        }
        if (strncasecmp(name, p->name, p->len) == 0){
            p->handler(value, p->offset, p->conf);
            break;
        }
        p ++;
    }
    if (p->name == NULL) {
        fprintf(stderr, "unsuport conf item: %s\n", name);
        return -1;
    }

    return 0;
}

int parse_line(char *start, char *end)
{
    char *name = start;
    char *value = NULL;

    char *p = start;
    while (p < end && *p != ' ' && *p != '\t' && *p != '=')
        p ++;
    if (p == end)
        goto ERROR;
    *p ++ = '\0';
    while (p < end && (*p == ' ' || *p == '\t' || *p == '='))
        p ++;
    if (p == end)
        goto ERROR;
    value = p;
    while (p < end && *p != '\n' && *p != ';')
        p ++;
    if (p == end)
        goto ERROR;
    if (*p == ';')
        *p = '\0';
    return parse_info(name, value);
ERROR:
    fprintf(stderr, "read empty line from config.\n");
    return -1;
}


int parse_conf(char *path)
{
    FILE *fp = fopen(path, "r");
    if (fp == NULL) {
        goto ERROR;
    }
    char *s = NULL;
    char *end = NULL;
    char line[2048];
    int len = 0;

    while (!feof(fp)) {
        s = fgets(line, 2048, fp);
        if (!s) {
            if (ferror(fp)) {
                goto ERROR;
            } else {
                break;
            }
        }
        s = line;
        len = strlen(s);
        if (len == 2048 - 1) {
            fprintf(stderr, "maybe read truncate line from config.\n");
            continue;
        }
        end = s + len;
        while (s < end && isspace(*s)) {
            s ++;
        }
        if (s == end) {
            fprintf(stderr, "read empty line from config.\n");
            continue;
        }
        if (s < end && (*s == '#' || (*s == '/' && *(s + 1) == '/'))) {
            continue;
        }
        if (parse_line(s, end)) {
            goto ERROR;
        }
    }
    fclose(fp);
    return 0;
ERROR:
    if (fp) {
       fclose(fp);
    }
    return -1;
}



void sniffer_log_request(request_info_t *info)
{
    char *p = NULL;
    log_output_t **log_p = &g_sniffer_conf.log_handlers[0];
    log_output_t *s = NULL;

    while (*log_p) {
        s = *log_p;
        p = s->log_handler(s->offset, (char*)info);
        if (!p)
            p = "-";
        fprintf(g_access_file, "\"%s\"\t", p);
        log_p ++;
    }
    fprintf(g_access_file, "\n");
    fflush(g_access_file);

}

void arrange_item(request_info_t *info, char *name, char *value, int name_len)
{
    char **s = NULL;
    log_output_t *tmp = &log_format[0];
    while (tmp->name_len) {
        if (tmp->name_len == name_len) 
            if (strncmp(name, tmp->name, name_len) == 0) {
                s = (char**)((char*)info + tmp->offset);
                *s = value;
                return;
            }
        tmp ++;
    }
    fprintf(stderr, "unsupport header: %s.\n", name);
}

#define undef_mode            (0xFF)
#define sniffer_request_mode  (0x11)
#define sniffer_response_mode (0x22)


int sniffer_analy_data(request_info_t *info, int mode)
{
    char *p = info->req_app_data;
    char *end = p + info->req_app_len;
    char *name = NULL;
    char *value = NULL;
	char *uri = NULL;
    int len = 0;
    int status = 0;
    
    if (mode == sniffer_response_mode) {
        while (p < end && *p != ' ') 
            p ++;
        if (p == end) return -1;
        p += 1;

        info->response_status = p;;
        while (p < end && isdigit(*p)) {
            status = status * 10 + *p - '0';
            p ++;
        }
        if (p == end) return -1;
        *p ++ = '\0';
            
    } else {
        info->uri = p;
        while (p < end && *p != ' ') 
            p ++;
        if (p == end) return -1;
        p += 1;

        if (strncmp(p, "/abc/", 5) == 0 \
            || strncmp(p, "/vpn/", 5) == 0 \
            || strncmp(p, "/gate/", 6) == 0) {
            return -1;
        }
        while (p < end && *p != ' ')
             p ++;
        if (p == end) return -1;
        *p ++ = '\0';
        
    }
    while (p < end - 1) {
        if (*p == '\r' && *(p + 1) == '\n') {
            p += 2;
            break;
        }
        p ++;
    }
    if (p == end - 1)
        return -1;
    
    name = p;
    while (p < end) {
         if (*p == ':' && *(p + 1) == ' ') {

             *p = '\0';
             len = p - name;

             p += 2;
             value = p;
             continue;
         }
        if (*p == '\r' && *(p + 1) == '\n') {
            *p = '\0';
            arrange_item(info, name, value, len);
            len = 0;
            p = p + 2;
            if (*p == '\r' && *(p + 1) == '\n')
                break;
            name = p;
            continue;
        }
        p ++;
    }
    return 0;
}

int sniffer_get_real_ip(char *ip, char *p, char **q)
{
    char buf[128] = {0};
    char *s = NULL;
    char *d = NULL;
    int n = 0;
    sprintf(buf, "grep %s %s | awk -F [:,] '{print $2, $3}' | awk 'END{print}'", ip, g_sniffer_conf.status_file);
    FILE *sp = popen(buf, "r");
    if (sp == NULL) {
        fprintf(g_error_file, "popen fail: %s.\n", ip);
        return -1;
    }
    n = fread(p, 1, 128, sp);
    pclose(sp);
    if (n < 24) {
        fprintf(g_error_file, "has no match info for: %s.\n", ip);
        return -1;
    }
    s = p;
    d = p + n;

    while(s < d) {
        if (*s == ' ')
            break;
        s ++;
    }
    if (s == d) {
        return -1;
    }
    *(s ++) = '\0';
    *q = s;
    p[n - 1]='\0';
    return 0;
}




int sniffer_decode_data(request_info_t *info, int len)
{
    struct iphdr *ip_h;
    struct tcphdr *tcp_h;
    struct udphdr *udp_h;
    struct ether_header *ether_h;
    unsigned int ip_h_len = 0;
    unsigned int tcp_h_len = 0;
    unsigned int ip_tot_len = 0;
    char **p = NULL;
    int  mode = undef_mode;
    time_t    t;

    info->cur = info->request_data + len;
    info->end = info->request_data + MAX_REQUEST_DATA_SIZE;

    if (info->end - info->cur < 48 + 48 + 16 + 32) {
        info->cur = calloc(1, 2048);
        if (!info->cur) {
            fprintf(g_error_file, "calloc too large segment fail.\n");
            return undef_mode;
        }
        info->extra = info->cur;
    }
    info->token = info->cur;
    info->mid_ip = NULL;
    info->src_ip = info->token + 64;
    info->dst_ip = info->src_ip + 16;
    info->src_port = info->dst_ip + 16;
    info->dst_port = info->src_port + 8;
    info->time = info->dst_port + 8;
    info->cur = info->time + 32;

    ip_h = (struct iphdr*)(info->request_data);
    if (ip_h->protocol != 0x06) 
        return undef_mode;

    ip_h_len = ip_h->ihl << 2;
    ip_tot_len = ntohs(ip_h->tot_len);

    tcp_h = (struct tcphdr*)((char*)ip_h + ip_h_len);
    tcp_h_len = tcp_h->doff << 2;

    info->req_app_len = ip_tot_len - ip_h_len - tcp_h_len;
    info->req_app_data = (char*)tcp_h + tcp_h_len;

    if (info->req_app_len == 0) 
        return undef_mode;

    t = time(NULL);
    ctime_r(&t, info->time);
    info->time[strlen(info->time) - 1] = '\0';
    info->cur_time = t;

    p = &g_request_method[0];
    while (*p) {
        if (memcmp(*p, info->req_app_data, strlen(*p)) == 0) {
            mode = sniffer_request_mode;
            break;
        }
        p ++;
    }
    if (mode == undef_mode) {
        p = &g_response_method[0];
        while (*p) {
            if (memcmp(*p, info->req_app_data, strlen(*p)) == 0) {
                mode = sniffer_response_mode;
                break;
            }
            p ++;
        }    
    }
    if (mode == undef_mode) 
        return mode;
    strcpy(info->src_ip, inet_ntoa(*((struct in_addr*)&ip_h->saddr)));    
    strcpy(info->dst_ip, inet_ntoa(*((struct in_addr*)&ip_h->daddr)));

    if (mode == sniffer_request_mode) {
        if (sniffer_get_real_ip(info->src_ip, info->token, &info->mid_ip)) {
            fprintf(g_error_file, "get real ip from: %s fail.\n", info->src_ip);
            return undef_mode;
        }
    } else {
        if (sniffer_get_real_ip(info->dst_ip, info->token, &info->mid_ip)) {
            fprintf(g_error_file, "get real ip from: %s fail.\n", info->dst_ip);
            return undef_mode;
        }
    }

    snprintf(info->src_port, 8, "%d", ntohs(tcp_h->source));
    snprintf(info->dst_port, 8, "%d", ntohs(tcp_h->dest));

    info->packet_info.s_addr = ip_h->saddr;
    info->packet_info.d_addr = ip_h->daddr;
    info->packet_info.s_port = tcp_h->source;
    info->packet_info.d_port = tcp_h->dest;
    return mode;

}
int rawSocket(char *dev_name)
{
    int raw_sock_fd;
    struct sockaddr_ll sll;
    struct ifreq ifstruct;

    memset(&sll, 0, sizeof(struct sockaddr_ll));
    strcpy(ifstruct.ifr_name, dev_name);

    raw_sock_fd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
    if(raw_sock_fd < 0) {
        printf("create raw socket failed::%s\n",strerror(errno));
        return -1;
    }

    if (ioctl(raw_sock_fd, SIOCGIFINDEX, &ifstruct) == -1) {
        printf("ioctl SIOCGIFINDEX [%s] Error!!!", dev_name);
        close(raw_sock_fd);
        return -1;
    }

    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifstruct.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    /*
    sll.sll_hatype   = ARPHRD_ETHER;
    sll.sll_pkttype  = PACKET_OTHERHOST;
    sll.sll_halen    = ETH_ALEN;
    sll.sll_addr[6]  = 0;
    sll.sll_addr[7]  = 0;

    if (ioctl(raw_sock_fd, SIOCGIFHWADDR, &ifstruct) == -1) {
        printf("\nioctl SIOCGIFHWADDR [%s] Error!!!", dev_name);
        close(raw_sock_fd);
        return -1;
    }
    */
    if (ioctl(raw_sock_fd, SIOCGIFFLAGS, &ifstruct) == -1) {
        printf("ioctl SIOCGIFFLAGS [%s] Error!!!", dev_name);
        close(raw_sock_fd);
        return -1;
    }

    ifstruct.ifr_flags |= IFF_PROMISC;
    if (ioctl(raw_sock_fd, SIOCSIFFLAGS, &ifstruct) == -1) {
        printf("Set [%s] promisc error\n", dev_name);
        close(raw_sock_fd);
        return -1;
    }

    if (bind(raw_sock_fd, (struct sockaddr *)&sll, sizeof(struct sockaddr_ll)) == -1) {
        printf("Bind %s Error!", dev_name);
        close(raw_sock_fd);
        return -1;
    }

    return raw_sock_fd;
}

int set_filter(int *sock)
{
    struct sock_filter code[] = {
               { 0x28, 0, 0, 0x0000000c },
               { 0x15, 0, 14, 0x00000800 },
               { 0x30, 0, 0, 0x00000017 },
               { 0x15, 0, 12, 0x00000006 },
               { 0x28, 0, 0, 0x00000014 },
               { 0x45, 10, 0, 0x00001fff },
               { 0xb1, 0, 0, 0x0000000e },
               { 0x50, 0, 0, 0x0000001a },
               { 0x54, 0, 0, 0x000000f0 },
               { 0x74, 0, 0, 0x00000002 },
               { 0xc, 0, 0, 0x00000000 },
               { 0x7, 0, 0, 0x00000000 },
               { 0x40, 0, 0, 0x0000000e },
               { 0x15, 1, 0, 0x47455420 },
               { 0x15, 0, 1, 0x504f5354 },
               { 0x6, 0, 0, 0x0000ffff },
               { 0x6, 0, 0, 0x00000000 }
    };
    struct sock_fprog filter;
    filter.len = 17;
    filter.filter = code;

    int ret = setsockopt(*sock, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter));
    if (ret < 0) {
        perror("setsockopt");
        return -1;
    }
    return 0;
}


int main(int argc, char **argv)
{
    char *conf_file = NULL;
    char *select_interface = NULL;
    request_info_t *p = NULL;

    struct sockaddr_in rcvaddr;
    int sock = 0;
    int len = 0;
    int rval = 0;
    int mode = 0;
    char c = 0;

    while ((c = getopt(argc, argv, "c:i:")) != -1) {
        switch(c) {
            case 'c':
                conf_file = optarg;
                break;
            case 'i':
                select_interface = optarg;
                break;
            default:
                fprintf(stderr, "invalid arg.\n");
                exit(-1);
        }
    }

    if (conf_file) {
       parse_conf(conf_file);
    }
    if (select_interface == NULL) {
        fprintf(stderr, "lack interface info.\n");
        return -1;
    }
    g_access_file = fopen(g_sniffer_conf.access_log, "w");
    if (g_access_file == NULL) {
        fprintf(stderr, "open access file fail.\n");
        return -1;
    }
    g_error_file = fopen(g_sniffer_conf.error_log, "w");
    if (g_error_file == NULL) {
        fprintf(stderr, "open error file fail.\n");
        return -1;
    }

    sock = rawSocket(select_interface);
    if (sock == -1) {
         fprintf(stderr, "set promisc fail.\n");
         return -1;
    }
    /*
    if (set_filter(&sock) == -1) {
         fprintf(stderr, "set filter fail.\n");
        return -1;
    }
    */
    

    init_g_free_buf();
    pthread_t clean_p;

    if((pthread_create(&clean_p, NULL, sniffer_hash_aging, NULL))==-1) {
        fprintf(stderr, "create clean thread fail.\n");
        return -1;
    }
    
    len = sizeof(struct sockaddr);
    p = NULL;

    while ( 1 ) {
        p = get_free_request();
        if (!p) {
            p = calloc(1, sizeof(request_info_t));
            if (!p) {
                fprintf(g_error_file, "get extra request_info_t fail.\n");
                sleep(1);
                continue;
            }
        }

        rval = recvfrom(sock, p->request_data, MAX_REQUEST_DATA_SIZE, \
                        0,(struct sockaddr*)&rcvaddr,&len);
        if(rval > 0) {
            mode = sniffer_decode_data(p, rval);
            if (mode == undef_mode) {
                release_request_info(p);
                continue;
            }
            rval = sniffer_analy_data(p, mode);
            if (rval) {
                release_request_info(p);
                continue;
            }
            if (mode == sniffer_request_mode) {
                sniffer_hash_add(p);
            } else {
                sniffer_hash_mergh(p);
                if (p->partern)
                    sniffer_log_request(p);
                release_request_info(p);
            }
            
        }
    }
    fclose(g_access_file);
    fclose(g_error_file);
    return 0;
}
