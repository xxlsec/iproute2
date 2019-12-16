/* sqlite files 'in rest' and 'in use' states
 * NOTE: place DECRYPTED path to /tmp (RAM) in production
 */
#define MPP_DB_FILE_ENCRYPTED "device.db"
#define MPP_DB_FILE_DECRYPTED "tmp/device.db"

/* Field order in comma separeted payload string 
 */
#define NICKNAME 0
#define IPADDR 1
#define MKEY 2
#define GKEY 3
#define MACADDR 4
#define MACSECKEY 5
#define MACSECIP 6

int ismppdbavailable(const char * filename);
int showmyconfig(void);
int showconstellation(int (*callback)(void*,int,char**,char**));
int setpayload(int index, char* payload);
int getpayload(char *payload);
int getpeerspayload(char *payload);
int writepayload(char *payload);
int getpayloadfield(int index, char* fielddata);
int getpeerspayloadfield(int index, char* fielddata);
int showgroupkey(void);
int showmulticastkey(void);
int initemptypayload(void);
