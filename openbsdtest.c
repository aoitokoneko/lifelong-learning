#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#define MAX_DEVICES 254
#define SCAN_TIMEOUT 3
#define ARP_CACHE_FILE "/proc/net/arp"
#define KNOWN_DEVICES_FILE "/etc/known_devices.conf"

/* デバイス情報構造体 */
typedef struct {
   char ip[INET_ADDRSTRLEN];
   char mac[18];
   char hostname[256];
   int responsive;
   time_t last_seen;
   int is_known;
} device_info_t;

/* グローバル変数 */
static device_info_t devices[MAX_DEVICES];
static int device_count = 0;
static char gateway_ip[INET_ADDRSTRLEN];
static char network_base[INET_ADDRSTRLEN];
static int network_mask = 24;

/* 関数プロトタイプ */
static int get_gateway_info(void);
static int scan_network(void);
static int get_arp_table(void);
static int resolve_hostnames(void);
static int load_known_devices(void);
static void analyze_security_status(void);
static void print_results(void);
static int is_port_open(const char *ip, int port);
static void get_device_details(device_info_t *device);
static char *get_vendor_from_mac(const char *mac);

/* OpenBSDのセキュリティ機能を活用 */
static int
init_security_context(void)
{
#ifdef __OpenBSD__
   /* pledge: 必要最小限の権限のみ許可 */
   if (pledge("stdio rpath wpath cpath inet dns proc exec", NULL) == -1) {
       perror("pledge");
       return -1;
   }

   /* unveil: アクセス可能なファイルパスを制限 */
   if (unveil("/etc", "r") == -1 ||
       unveil("/proc", "r") == -1 ||
       unveil("/usr/bin", "x") == -1 ||
       unveil("/bin", "x") == -1) {
       perror("unveil");
       return -1;
   }

   /* unveilの設定完了 */
   if (unveil(NULL, NULL) == -1) {
       perror("unveil lock");
       return -1;
   }
#endif
   return 0;
}

/* ゲートウェイ情報を取得 */
static int
get_gateway_info(void)
{
   int mib[6];
   size_t needed;
   char *buf, *next, *lim;
   struct rt_msghdr *rtm;
   struct sockaddr_in *sin;
   struct sockaddr *sa;
   int found = 0;

   mib[0] = CTL_NET;
   mib[1] = AF_ROUTE;
   mib[2] = 0;
   mib[3] = AF_INET;
   mib[4] = NET_RT_FLAGS;
   mib[5] = RTF_GATEWAY;

   if (sysctl(mib, 6, NULL, &needed, NULL, 0) == -1) {
       perror("sysctl routing table size");
       return -1;
   }

   if ((buf = malloc(needed)) == NULL) {
       perror("malloc");
       return -1;
   }

   if (sysctl(mib, 6, buf, &needed, NULL, 0) == -1) {
       perror("sysctl routing table");
       free(buf);
       return -1;
   }

   lim = buf + needed;
   for (next = buf; next < lim; next += rtm->rtm_msglen) {
       rtm = (struct rt_msghdr *)next;
       sa = (struct sockaddr *)(rtm + 1);

       if (rtm->rtm_flags & RTF_GATEWAY &&
           rtm->rtm_addrs & RTA_DST &&
           rtm->rtm_addrs & RTA_GATEWAY) {

           /* デフォルトルートをチェック */
           sin = (struct sockaddr_in *)sa;
           if (sin->sin_addr.s_addr == INADDR_ANY) {
               /* ゲートウェイアドレスを取得 */
               sa = (struct sockaddr *)((char *)sa +
                   ((sa->sa_len + 3) & ~3));
               sin = (struct sockaddr_in *)sa;

               if (sin->sin_family == AF_INET) {
                   strcpy(gateway_ip, inet_ntoa(sin->sin_addr));
                   found = 1;
                   break;
               }
           }
       }
   }

   free(buf);

   if (!found) {
       fprintf(stderr, "ゲートウェイが見つかりませんでした\n");
       return -1;
   }

   /* ネットワークベースアドレスを計算 */
   struct in_addr addr;
   inet_aton(gateway_ip, &addr);
   addr.s_addr &= htonl(0xFFFFFF00); /* /24マスクを仮定 */
   strcpy(network_base, inet_ntoa(addr));

   printf("ゲートウェイ: %s\n", gateway_ip);
   printf("ネットワーク: %s/%d\n", network_base, network_mask);
   return 0;
}

/* ネットワークスキャンを実行 */
static int
scan_network(void)
{
   struct sockaddr_in target;
   int sock, flags, result;
   fd_set writefds, readfds;
   struct timeval timeout;
   char target_ip[INET_ADDRSTRLEN];
   struct in_addr base_addr;

   printf("ネットワークスキャンを開始します...\n");
   inet_aton(network_base, &base_addr);

   for (int i = 1; i < 255; i++) {
       struct in_addr current_addr;
       current_addr.s_addr = base_addr.s_addr | htonl(i);
       strcpy(target_ip, inet_ntoa(current_addr));

       /* TCPソケットを作成 */
       if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
           continue;
       }

       /* ノンブロッキングモードに設定 */
       flags = fcntl(sock, F_GETFL, 0);
       fcntl(sock, F_SETFL, flags | O_NONBLOCK);

       memset(&target, 0, sizeof(target));
       target.sin_family = AF_INET;
       target.sin_port = htons(80); /* HTTP port for connectivity test */
       inet_aton(target_ip, &target.sin_addr);

       result = connect(sock, (struct sockaddr*)&target, sizeof(target));

       if (result < 0 && errno == EINPROGRESS) {
           FD_ZERO(&writefds);
           FD_SET(sock, &writefds);
           timeout.tv_sec = 1;
           timeout.tv_usec = 0;

           if (select(sock + 1, NULL, &writefds, NULL, &timeout) > 0) {
               socklen_t len = sizeof(result);
               getsockopt(sock, SOL_SOCKET, SO_ERROR, &result, &len);

               if (result == 0 || result == ECONNREFUSED) {
                   /* デバイスが応答している */
                   strcpy(devices[device_count].ip, target_ip);
                   devices[device_count].responsive = 1;
                   devices[device_count].last_seen = time(NULL);
                   device_count++;
                   printf("発見: %s\n", target_ip);
               }
           }
       }

       close(sock);

       if (device_count >= MAX_DEVICES) break;
   }

   printf("スキャン完了: %d台のデバイスを発見\n", device_count);
   return 0;
}

/* ARPテーブルから情報を取得 */
static int
get_arp_table(void)
{
   FILE *fp;
   char line[256];
   char ip[INET_ADDRSTRLEN], mac[18], interface[16];
   int type, flags;

   /* OpenBSDのarp -aコマンドを使用 */
   if ((fp = popen("/usr/sbin/arp -a", "r")) == NULL) {
       perror("arp command failed");
       return -1;
   }

   while (fgets(line, sizeof(line), fp)) {
       /* arp -aの出力を解析 */
       if (sscanf(line, "%*s (%15[^)]) at %17s", ip, mac) == 2) {
           /* 既存のデバイス情報を更新または新規追加 */
           int found = 0;
           for (int i = 0; i < device_count; i++) {
               if (strcmp(devices[i].ip, ip) == 0) {
                   strcpy(devices[i].mac, mac);
                   found = 1;
                   break;
               }
           }

           if (!found && device_count < MAX_DEVICES) {
               strcpy(devices[device_count].ip, ip);
               strcpy(devices[device_count].mac, mac);
               devices[device_count].responsive = 0; /* ARPからの情報 */
               devices[device_count].last_seen = time(NULL);
               device_count++;
           }
       }
   }

   pclose(fp);
   return 0;
}

/* ホスト名を解決 */
static int
resolve_hostnames(void)
{
   for (int i = 0; i < device_count; i++) {
       struct sockaddr_in addr;
       char hostname[256];

       memset(&addr, 0, sizeof(addr));
       addr.sin_family = AF_INET;
       inet_aton(devices[i].ip, &addr.sin_addr);

       if (getnameinfo((struct sockaddr*)&addr, sizeof(addr),
                      hostname, sizeof(hostname), NULL, 0, 0) == 0) {
           strcpy(devices[i].hostname, hostname);
       } else {
           strcpy(devices[i].hostname, "Unknown");
       }
   }

   return 0;
}

/* 既知のデバイス情報を読み込み */
static int
load_known_devices(void)
{
   FILE *fp;
   char line[512];
   char known_mac[18];

   if ((fp = fopen(KNOWN_DEVICES_FILE, "r")) == NULL) {
       printf("既知デバイス設定ファイルが見つかりません: %s\n",
              KNOWN_DEVICES_FILE);
       return 0; /* エラーではない */
   }

   while (fgets(line, sizeof(line), fp)) {
       if (line[0] == '#' || strlen(line) < 17) continue;

       if (sscanf(line, "%17s", known_mac) == 1) {
           /* 既知のMACアドレスとマッチング */
           for (int i = 0; i < device_count; i++) {
               if (strcasecmp(devices[i].mac, known_mac) == 0) {
                   devices[i].is_known = 1;
                   break;
               }
           }
       }
   }

   fclose(fp);
   return 0;
}

/* MACアドレスからベンダー情報を取得 */
static char *
get_vendor_from_mac(const char *mac)
{
   static char vendor[64];
   char oui[9];

   if (strlen(mac) < 8) return "Unknown";

   /* OUI (最初の3バイト) を抽出 */
   snprintf(oui, sizeof(oui), "%.2s%.2s%.2s", mac, mac+3, mac+6);

   /* 主要ベンダーの簡易識別 */
   if (strncasecmp(oui, "001122", 6) == 0) strcpy(vendor, "Apple");
   else if (strncasecmp(oui, "aabbcc", 6) == 0) strcpy(vendor, "Samsung");
   else if (strncasecmp(oui, "112233", 6) == 0) strcpy(vendor, "Intel");
   else strcpy(vendor, "Unknown");

   return vendor;
}

/* デバイスの詳細情報を取得 */
static void
get_device_details(device_info_t *device)
{
   /* 一般的なポートをチェック */
   int common_ports[] = {22, 23, 80, 443, 8080, 0};

   for (int i = 0; common_ports[i] != 0; i++) {
       if (is_port_open(device->ip, common_ports[i])) {
           printf("  - ポート %d が開いています\n", common_ports[i]);
       }
   }
}

/* ポートスキャン */
static int
is_port_open(const char *ip, int port)
{
   int sock;
   struct sockaddr_in target;
   int result;
       if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
       return 0;
   }

   /* タイムアウト設定 */
   struct timeval timeout;
   timeout.tv_sec = 1;
   timeout.tv_usec = 0;
   setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
   setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

   memset(&target, 0, sizeof(target));
   target.sin_family = AF_INET;
   target.sin_port = htons(port);
   inet_aton(ip, &target.sin_addr);

   result = connect(sock, (struct sockaddr*)&target, sizeof(target));
   close(sock);

   return (result == 0);
}

/* セキュリティ状況を分析 */
static void
analyze_security_status(void)
{
   int unknown_devices = 0;
   int suspicious_devices = 0;
   time_t current_time = time(NULL);

   printf("\n=== セキュリティ分析結果 ===\n");

   for (int i = 0; i < device_count; i++) {
       if (!devices[i].is_known) {
           unknown_devices++;

           /* 疑わしいデバイスの条件をチェック */
           int is_suspicious = 0;

           /* 1. ホスト名が解決できない */
           if (strcmp(devices[i].hostname, "Unknown") == 0) {
               is_suspicious = 1;
           }

           /* 2. 一般的でないMACアドレスパターン */
           if (strncmp(devices[i].mac, "00:00:00", 8) == 0 ||
               strncmp(devices[i].mac, "ff:ff:ff", 8) == 0) {
               is_suspicious = 1;
           }

           /* 3. 最近接続されたデバイス (過去1時間以内) */
           if (current_time - devices[i].last_seen < 3600) {
               printf("⚠️  新規接続デバイス検出: %s\n", devices[i].ip);
           }

           if (is_suspicious) {
               suspicious_devices++;
               printf("🚨 疑わしいデバイス: %s (MAC: %s)\n",
                      devices[i].ip, devices[i].mac);
           }
       }
   }

   printf("\n📊 統計情報:\n");
   printf("  総デバイス数: %d\n", device_count);
   printf("  既知デバイス: %d\n", device_count - unknown_devices);
   printf("  未知デバイス: %d\n", unknown_devices);
   printf("  疑わしいデバイス: %d\n", suspicious_devices);

   if (suspicious_devices > 0) {
       printf("\n🔴 セキュリティアラート: 疑わしいデバイスが検出されました！\n");
       printf("   ネットワーク管理者に確認することをお勧めします。\n");
   } else if (unknown_devices > 0) {
       printf("\n🟡 注意: 未知のデバイスが検出されました。\n");
       printf("   必要に応じて既知デバイスリストを更新してください。\n");
   } else {
       printf("\n🟢 セキュリティ状況: 正常\n");
       printf("   すべてのデバイスが既知のものです。\n");
   }
}

/* 結果を出力 */
static void
print_results(void)
{
   printf("\n=== ネットワークデバイス一覧 ===\n");
   printf("%-15s %-17s %-25s %-10s %-10s %s\n",
          "IPアドレス", "MACアドレス", "ホスト名", "応答", "既知", "ベンダー");
   printf("-------------------------------------------------------------------------------\n");

   for (int i = 0; i < device_count; i++) {
       char *vendor = get_vendor_from_mac(devices[i].mac);
       char time_str[64];
       struct tm *tm_info = localtime(&devices[i].last_seen);
       strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);

       printf("%-15s %-17s %-25s %-10s %-10s %s\n",
              devices[i].ip,
              strlen(devices[i].mac) > 0 ? devices[i].mac : "N/A",
              devices[i].hostname,
              devices[i].responsive ? "Yes" : "No",
              devices[i].is_known ? "Yes" : "No",
              vendor);

       /* 詳細情報の表示 */
       if (!devices[i].is_known) {
           printf("  └─ 最終確認: %s", time_str);
           if (devices[i].responsive) {
               printf(" (アクティブ)");
               get_device_details(&devices[i]);
           }
           printf("\n");
       }
   }
}

/* 既知デバイス設定ファイルのサンプル作成 */
static void
create_sample_config(void)
{
   FILE *fp;

   if (access(KNOWN_DEVICES_FILE, F_OK) == 0) {
       return; /* 既に存在する */
   }

   if ((fp = fopen(KNOWN_DEVICES_FILE, "w")) == NULL) {
       return; /* 作成できない場合は無視 */
   }

   fprintf(fp, "# 既知デバイス設定ファイル\n");
   fprintf(fp, "# 1行に1つのMACアドレスを記述してください\n");
   fprintf(fp, "# 例:\n");
   fprintf(fp, "# aa:bb:cc:dd:ee:ff  # 自分のPC\n");
   fprintf(fp, "# 11:22:33:44:55:66  # スマートフォン\n");
   fprintf(fp, "\n");

   /* 現在検出されたデバイスをコメントアウトして追加 */
   fprintf(fp, "# 現在検出されているデバイス:\n");
   for (int i = 0; i < device_count; i++) {
       if (strlen(devices[i].mac) > 0) {
           fprintf(fp, "# %s  # %s (%s)\n",
                   devices[i].mac, devices[i].ip, devices[i].hostname);
       }
   }

   fclose(fp);
   printf("サンプル設定ファイルを作成しました: %s\n", KNOWN_DEVICES_FILE);
}

/* メイン関数 */
int
main(int argc, char *argv[])
{
   printf("ホームネットワークセキュリティスキャナー v1.0\n");
   printf("OpenBSD 7.7専用版\n\n");

   /* セキュリティコンテキストの初期化 */
   if (init_security_context() != 0) {
       fprintf(stderr, "セキュリティ初期化に失敗しました\n");
       return 1;
   }

   /* 実行権限チェック */
   if (geteuid() != 0) {
       printf("注意: root権限で実行することを推奨します\n");
       printf("一部の機能が制限される可能性があります\n\n");
   }

   /* ゲートウェイ情報取得 */
   if (get_gateway_info() != 0) {
       fprintf(stderr, "ゲートウェイ情報の取得に失敗しました\n");
       return 1;
   }

   /* ネットワークスキャン実行 */
   if (scan_network() != 0) {
       fprintf(stderr, "ネットワークスキャンに失敗しました\n");
       return 1;
   }

   /* ARPテーブル情報取得 */
   printf("ARPテーブル情報を取得中...\n");
   get_arp_table();

   /* ホスト名解決 */
   printf("ホスト名を解決中...\n");
   resolve_hostnames();

   /* 既知デバイス情報読み込み */
   load_known_devices();

   /* 設定ファイルが存在しない場合はサンプルを作成 */
   create_sample_config();

   /* 結果出力 */
   print_results();

   /* セキュリティ分析 */
   analyze_security_status();

   printf("\n=== 推奨事項 ===\n");
   printf("1. 未知のデバイスが検出された場合は、物理的にネットワークから\n");
   printf("   切断されているか確認してください\n");
   printf("2. 定期的にパスワードを変更し、WPA3暗号化を使用してください\n");
   printf("3. 不要なポートやサービスは無効化してください\n");
   printf("4. ファームウェアを最新の状態に保ってください\n");
   printf("5. ゲストネットワークの使用を検討してください\n\n");

   return 0;
}
