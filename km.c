/*
URL for cloning: https://github.com/shanebishop/pH-rewrite.git

Notes:
-Know when to use retreive_pH_profile_by_filename instead of retreive_pH_profile_by_pid
-When retrieving the PID of a process, use pid_vnr(task_tgid(tsk));, where tsk is the task_struct of 
the particular process
-Make sure that syscalls are still processed even while waiting to hear back from the user
-Make sure to update filenames and stuff when done (including ebbchar_init, ebbchar_exit, and 
ebbchar_mutex)
-Never use booleans to stop code from running after a fatal error, instead use ASSERT with a detailed
error message (code should ONLY stop running on ASSERT or rmmod)
*/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/mutex.h>

#include <linux/kprobes.h>   // For kprobes
#include <linux/slab.h>      // For kmalloc
#include <linux/vmalloc.h>   // For vmalloc

#include "system_call_prototypes.h"
#include "ebbcharmutex.h"

#define  DEVICE_NAME "ebbchar"
#define  CLASS_NAME  "ebb"

MODULE_LICENSE("GPL"); // Don't ever forget this line!

// Anil's definitions
//#define PH_NUM_SYSCALLS 256 // Size of array
#define PH_NUM_SYSCALLS num_syscalls // Size of array
#define PH_COUNT_PAGE_MAX (PAGE_SIZE / PH_NUM_SYSCALLS)
#define PH_MAX_PAGES (PH_NUM_SYSCALLS / PH_COUNT_PAGE_MAX)
#define PH_MAX_SEQLEN 9
#define PH_MAX_DISK_FILENAME 256
#define PH_LOCALITY_WIN 128
#define PH_FILE_MAGIC_LEN 20
#define PH_EMPTY_SYSCALL 255 // Note: This value is used as the "no system call" marker in sequences"

#define PH_LOG_ERR 1      /* real errors */
#define PH_LOG_STATE 2    /* changes in state */
#define PH_LOG_ACTION 3   /* actions pH takes (delays) */
#define PH_LOG_IO 4    /* I/O operations (read/write profiles) */

#define err(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_ERR) { \
                printk(KERN_ERR "pH: " format "\n" , ## arg); \
        } \
}

#define state(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_STATE) { \
                printk(KERN_INFO "pH: " format "\n" , ## arg); \
        } \
}

#define action(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_ACTION) { \
                printk(KERN_DEBUG "pH: " format "\n" , ## arg); \
        } \
}

#define io(format, arg...) \
{ \
        if (pH_loglevel >= PH_LOG_IO) { \
                printk(KERN_DEBUG "pH: " format "\n" , ## arg); \
        } \
}

// My definitions
#define ASSERT(x)                                                       \
do {    if (x) break;                                                   \
        printk(KERN_EMERG "### ASSERTION FAILED %s: %s: %d: %s\n",      \
               __FILE__, __func__, __LINE__, #x); dump_stack(); BUG();  \
} while (0)

static int    majorNumber;

const char *PH_FILE_MAGIC = "pH profile 0.18\n";

static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops =
{
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
};

// Anil's structs
typedef int pH_seqflags;

typedef struct pH_seq {
	// My new fields
	struct pH_seq* next; // For linked list stack implementation

	// Anil's old fields
	int last; // seq is a circular array; this is its end
	int length;
	u8 data[PH_MAX_SEQLEN]; // Current sequence being filled or processed - initialized to PH_EMPTY_SYSCALL initially
	struct list_head seqList;
} pH_seq;

typedef struct pH_profile_data {
	int sequences;					// # sequences that have been inserted NOT the number of lookahead pairs
	unsigned long last_mod_count;	// # syscalls since last modification
	unsigned long train_count;		// # syscalls seen during training
	//void *pages[PH_MAX_PAGES];
	//int current_page;				// pages[current_page] contains free space
	//int count_page;					// How many arrays have been allocated in the current page
	pH_seqflags *entry[PH_NUM_SYSCALLS];
} pH_profile_data;

typedef struct pH_profile pH_profile;

struct pH_profile {
	// My new fields
	struct hlist_node hlist; // Must be first field
	int identifier;
	//spinlock_t freeing_lock;
	
	// Anil's old fields
	int normal;			// Is test profile normal?
	int frozen;			// Is train profile frozen (potential normal)?
	time_t normal_time;	// When will frozen become true normal?
	int length;
	unsigned long count;// Number of calls seen by this profile
	int anomalies;		// NOT LFC - decide if normal should be reset
	pH_profile_data train, test;
	char *filename;
	atomic_t refcount;
	pH_profile *next;
	//struct file *seq_logfile;
	pH_seq seq;
	spinlock_t* lock;
	bool is_temp_profile;
};

typedef struct pH_seq_logrec {
        unsigned long count;
        int pid;
        struct timespec time;
        pH_seq seq;
} pH_seq_logrec;

#define PH_CALLREC_SYSCALL 0
#define PH_CALLREC_FORK    1
#define PH_CALLREC_EXECVE  2

typedef struct pH_call_logrec {
        u16 pid;
        union {
                u16 syscall;      /* type = 0 */
                u16 child_pid;    /* type = 1 (fork) */
                u16 filename_len; /* type = 2 (execve) */
        } u;
        unsigned long count;
        long sec;
        long nsec;
        u8 type;          /* 0 = regular call, 1 = fork, 2, execve */
} pH_call_logrec;

typedef struct pH_locality {
	u8 win[PH_LOCALITY_WIN];
	int first;
	int total;
	int max;
} pH_locality;

// My own structs
typedef struct pH_task_struct { // My own version of a pH_task_state
	struct pH_task_struct* next; // For linked lists
	struct pH_task_struct* prev;
	long process_id;
	pH_locality alf;
	pH_seq* seq;
	int delay;
	unsigned long count;
	pH_profile* profile; // Pointer to appropriate profile
	struct task_struct* task_struct; // Pointer to corresponding task_struct
	struct pid* pid; // Pointer to corresponding struct pid
	spinlock_t lock;
} pH_task_struct;

typedef struct read_filename {
	char* filename;
	struct read_filename* next;
} read_filename;

typedef struct task_struct_wrapper {
	struct task_struct* task_struct;
	struct task_struct_wrapper* next;
} task_struct_wrapper;

static void jhandle_signal(struct ksignal*, struct pt_regs*);

struct jprobe handle_signal_jprobe = {
	.entry = jhandle_signal,
	//.kp = {
	//	.symbol_name = "handle_signal",
	//},
};

/*
static long jsys_sigreturn(struct pt_regs*);

struct jprobe sys_sigreturn_jprobe = {
	.entry = jsys_sigreturn,
	.kp = {
		.symbol_name = "sys_sigreturn",
	},
};
*/

/*
static long jsys_rt_sigreturn(void);

struct jprobe sys_sigreturn_jprobe = {
	.entry = jsys_rt_sigreturn,
};

static void jdo_signal(struct pt_regs* regs);

struct jprobe do_signal_jprobe = {
	.entry = jdo_signal,
};
*/

/* this was atomic, but now we need a long - so, we could make
   a spinlock for this */
unsigned long pH_syscall_count = 0;
//spinlock_t pH_syscall_count_lock = SPIN_LOCK_UNLOCKED;

pH_profile *pH_profile_list = NULL;
int pH_default_looklen = 9;
struct file *pH_logfile = NULL;
int pH_delay_factor = 0;
unsigned int pH_normal_factor = 128;
#define pH_normal_factor_den 32        /* a define to make the asm better */
int pH_aremonitoring = 0;
int pH_monitorSignal = 0;
int pH_mod_min = 500;
int pH_normal_min = 5;
int pH_anomaly_limit = 30;   /* test reset if profile->anomalies */
                                 /* exceeds this limit */
int pH_tolerize_limit = 12; /* train reset if LFC exceeds this limit */
int pH_loglevel = PH_LOG_ACTION;
int pH_log_sequences = 0;
int pH_suspend_execve = 0; /* min LFC to suspend execve's, 0 = no suspends */
int pH_suspend_execve_time = 3600 * 24 * 2;  /* time to suspend execve's */
int pH_normal_wait = 7 * 24 * 3600;/* seconds before putting normal to work */

// My global variables
#define SIGNAL_PRIVILEGE (1)
pH_task_struct* pH_task_struct_list = NULL; // List of processes currently being monitored
struct jprobe jprobes_array[num_syscalls];  // Array of jprobes (is this obsolete?)
long userspace_pid;                         // The PID of the userspace process
const char TRANSFER_OPERATION[2] = {'t', '\0'};
const char STOP_TRANSFER_OPERATION[3] = {'s', 't', '\0'};
const char READ_PROFILE_FROM_DISK[3] = {'r', 'b', '\0'};
char* output_string;                        // The string that will be sent to userspace
void* bin_receive_ptr;                      // The pointer for binary writes
bool done_waiting_for_user        = FALSE;
bool have_userspace_pid           = FALSE;
bool binary_read                  = FALSE;
bool user_process_has_been_loaded = FALSE;
bool module_inserted_successfully = FALSE;
spinlock_t pH_profile_list_sem;             // Lock for list of profiles
spinlock_t pH_task_struct_list_sem;         // Lock for process list
int profiles_created = 0;                   // Number of profiles that have been created
int successful_jsys_execves = 0;            // Number of successful jsys_execves
//struct task_struct* last_task_struct_in_sigreturn = NULL;
read_filename* read_filename_queue_front = NULL;
read_filename* read_filename_queue_rear = NULL;
spinlock_t read_filename_queue_lock;
task_struct_wrapper* task_struct_queue_front = NULL;
task_struct_wrapper* task_struct_queue_rear = NULL;
spinlock_t task_struct_queue_lock;

// Returns true if the process is being monitored, false otherwise
inline bool pH_monitoring(pH_task_struct* process) {
        return process->profile != NULL;
}

// Returns true if the profile is in use, false otherwise
inline bool pH_profile_in_use(pH_profile *profile)
{
        return atomic_read(&(profile->refcount)) > 0;
}

// Increments the profile's reference count
inline void pH_refcount_inc(pH_profile *profile)
{
        atomic_inc(&(profile->refcount));
}

// Decrements the profile's reference count
inline void pH_refcount_dec(pH_profile *profile)
{
        atomic_dec(&(profile->refcount));
}

// Initializes the profile's reference count
// Perhaps this should call atomic_set rather than directly changing the value
inline void pH_refcount_init(pH_profile *profile, int i)
{
        profile->refcount.counter = i;
}

// Adds an alloc'd profile to the profile list
void add_to_profile_llist(pH_profile* p) {
	pH_refcount_inc(p);
	
	ASSERT(spin_is_locked(&pH_profile_list_sem));
	//ASSERT(!spin_is_locked(&pH_task_struct_list_sem));
	
	//pr_err("%s: In add_to_profile_llist\n", DEVICE_NAME);
	
	// Checks for adding a NULL profile
	if (!p || p == NULL) {
		pr_err("%s: In add_to_profile_llist with a NULL profile\n", DEVICE_NAME);
		pH_refcount_dec(p);
		ASSERT(p != NULL);
		return;
	}
	
	if (pH_profile_list == NULL) {
		pr_err("%s: First element added to list\n", DEVICE_NAME);
		pH_profile_list = p;
		p->next = NULL;
	}
	else {
		/* // Old implementation
		pH_profile* iterator = pH_profile_list;
		
		while (iterator->next) iterator = iterator->next;
		
		iterator->next = p;
		p->next = NULL;
		*/
		
		pr_err("%s: Adding a new element...\n", DEVICE_NAME);
		p->next = pH_profile_list;
		pH_profile_list = p;
		ASSERT(pH_profile_list->next != NULL);
	}
	
	pH_refcount_dec(p);
	
	ASSERT(pH_profile_list != NULL);
	ASSERT(pH_profile_list == p);
	
	//pr_err("%s: Returning from add_to_profile_llist()...\n", DEVICE_NAME);
}

noinline const char* peek_read_filename_queue(void) {
	ASSERT(spin_is_locked(&read_filename_queue_lock));
	
	if (read_filename_queue_front == NULL) return NULL;
	
	return read_filename_queue_front->filename;
}

// I saw an "unable to handle kernel paging request error" occur that came from this function before,
// but the error actually happened in __kmalloc after a call to printk, so the problem may not stem
// from this function but rather from somewhere else
noinline void add_to_read_filename_queue(const char* filename) {
	ASSERT(spin_is_locked(&read_filename_queue_lock));
	ASSERT(filename != NULL);
	ASSERT(strlen(filename) > 1);
	ASSERT(!(!filename || filename == NULL || strlen(filename) < 1 || 
		!(*filename == '~' || *filename == '.' || *filename == '/')));
	
	pr_err("%s: In add_to_read_filename_queue\n", DEVICE_NAME);
	read_filename* to_add = kmalloc(sizeof(read_filename), GFP_ATOMIC);
	if (!to_add || to_add == NULL) {
		pr_err("%s: Out of memory in add_to_read_filename\n", DEVICE_NAME);
		return;
	}
	pr_err("%s: Allocated memory for to_add\n", DEVICE_NAME);
	
	char* save_filename = kmalloc(strlen(filename)+1, GFP_ATOMIC);
	if (!save_filename || save_filename == NULL) {
		pr_err("%s: Out of memory in add_to_read_filename\n", DEVICE_NAME);
		return;
	}
	pr_err("%s: Allocated memory for save_filename\n", DEVICE_NAME);
	
	strlcpy(save_filename, filename, strlen(filename)+1);
	pr_err("%s: save_filename is now [%s]\n", DEVICE_NAME, save_filename);
	ASSERT(save_filename != NULL);
	ASSERT(strlen(save_filename) > 1);
	ASSERT(!(!save_filename || save_filename == NULL || strlen(save_filename) < 1 || 
		!(*save_filename == '~' || *save_filename == '.' || *save_filename == '/')));
	
	to_add->filename = save_filename;
	ASSERT(strlen(to_add->filename) > 1);
	to_add->next = NULL;
	pr_err("%s: Performed some setup in add_to_read_filename_queue\n", DEVICE_NAME);
	
	if (read_filename_queue_front == NULL) {
		read_filename_queue_front = to_add;
		read_filename_queue_rear = to_add;
		read_filename_queue_rear->next = NULL;
		pr_err("%s: Made it to end of if in add_to_read_filename_queue\n", DEVICE_NAME);
	} else {
		read_filename_queue_rear->next = to_add;
		read_filename_queue_rear = to_add;
		read_filename_queue_rear->next = NULL;
		pr_err("%s: Made it to end of else in add_to_read_filename_queue\n", DEVICE_NAME);
	}
	pr_err("%s: Made it past branching in add_to_read_filename_queue\n", DEVICE_NAME);
	
	ASSERT(read_filename_queue_front != NULL);
	ASSERT(strlen(read_filename_queue_front->filename) > 1);
	
	pr_err("%s: Front has filename [%s]\n", DEVICE_NAME, peek_read_filename_queue());
}

noinline void remove_from_read_filename_queue(void) {
	read_filename* to_return;
	
	ASSERT(spin_is_locked(&read_filename_queue_lock));
	
	if (read_filename_queue_front == NULL) return;
	
	to_return = read_filename_queue_front;
	read_filename_queue_front = read_filename_queue_front->next;
	kfree(to_return->filename);
	to_return->filename = NULL;
	kfree(to_return);
	to_return = NULL;
}

void add_to_task_struct_queue(task_struct_wrapper* t) {
	ASSERT(spin_is_locked(&task_struct_queue_lock));
	ASSERT(t != NULL);
	ASSERT(t->task_struct != NULL);
	
	if (task_struct_queue_front == NULL) {
		task_struct_queue_front = t;
		task_struct_queue_rear = t;
		task_struct_queue_rear->next = NULL;
	}
	else {
		task_struct_queue_rear->next = t;
		task_struct_queue_rear = t;
		task_struct_queue_rear->next = NULL;
	}
}

void remove_from_task_struct_queue(void) {
	ASSERT(spin_is_locked(&task_struct_queue_lock));
	ASSERT(task_struct_queue_front != NULL);
	
	task_struct_wrapper* to_remove = task_struct_queue_front;
	task_struct_queue_front = task_struct_queue_front->next;
	kfree(to_remove);
	to_remove = NULL;
}

inline struct task_struct* peek_task_struct_queue(void) {
	if (task_struct_queue_front == NULL) return NULL;
	
	return task_struct_queue_front->task_struct;
}

void pH_profile_mem2disk(pH_profile*, pH_disk_profile*);
int pH_profile_disk2mem(pH_disk_profile*, pH_profile*);
void pH_free_profile(pH_profile*);

int pH_write_profile(pH_profile* profile) {
	pH_disk_profile* disk_profile = NULL;
	pH_profile* temp_profile = NULL;
	
	ASSERT(profile != NULL);
	
	temp_profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
	if (!temp_profile) {
		pr_err("%s: Unable to allocate memory for temp_profile\n", DEVICE_NAME);
		return -ENOMEM;
	}
	
	disk_profile = __vmalloc(sizeof(pH_disk_profile), GFP_ATOMIC, PAGE_KERNEL);
	if (!disk_profile) {
		pr_err("%s: Unable to allocate memory for disk_profile\n", DEVICE_NAME);
		kfree(temp_profile);
		temp_profile = NULL;
		return -ENOMEM;
	}
	
	pH_profile_mem2disk(profile, disk_profile);
	
	ASSERT(profile->normal == disk_profile->normal);
	ASSERT(profile->frozen == disk_profile->frozen);
	ASSERT(profile->normal_time == disk_profile->normal_time);
	ASSERT(profile->length == disk_profile->length);
	ASSERT(profile->count == disk_profile->count);
	ASSERT(profile->anomalies == disk_profile->anomalies);
	ASSERT(strcmp(profile->filename, disk_profile->filename) == 0);
	
	pH_profile_disk2mem(disk_profile, temp_profile);
	
	vfree(disk_profile);
	disk_profile = NULL;
	
	ASSERT(profile->normal == temp_profile->normal);
	ASSERT(profile->frozen == temp_profile->frozen);
	ASSERT(profile->normal_time == temp_profile->normal_time);
	ASSERT(profile->length == temp_profile->length);
	ASSERT(profile->count == temp_profile->count);
	ASSERT(profile->anomalies == temp_profile->anomalies);
	ASSERT(strcmp(profile->filename, temp_profile->filename) == 0);
	
	pH_free_profile(temp_profile);
	temp_profile = NULL;
	
	return 0;
}

// Makes a new pH_profile and stores it in profile
// profile must be allocated before this function is called
int new_profile(pH_profile* profile, const char* filename, bool make_temp_profile) {
	int i;

	ASSERT(profile != NULL);

	// Increments profiles_created, and stores it as the identifier
	profiles_created++;
	profile->identifier = profiles_created;
	profile->is_temp_profile = make_temp_profile;

	profile->normal = 0; // We just started - not normal yet!
	profile->frozen = 0;
	profile->normal_time = 0;
	profile->anomalies = 0;
	profile->length = pH_default_looklen;
	profile->count = 0;
	//pr_err("%s: Got here 1 (new_profile)\n", DEVICE_NAME);

	// Allocates memory for the lock
	profile->lock = kmalloc(sizeof(spinlock_t), GFP_ATOMIC);
	if (!(profile->lock) || profile->lock == NULL) {
		pr_err("%s: Unable to allocate memory for profile->lock in new_profile()\n", DEVICE_NAME);
		vfree(profile);
		profile = NULL;
		return -ENOMEM;
	}
	spin_lock_init(profile->lock);
	//spin_lock_init(&(profile->freeing_lock));
	//pr_err("%s: Got here 2 (new_profile)\n", DEVICE_NAME);

	profile->train.sequences = 0;
	profile->train.last_mod_count = 0;
	profile->train.train_count = 0;
	//profile->train.current_page = 0;
	//profile->train.count_page = 0;

	// Initializes entry array to NULL
	for (i=0; i<PH_NUM_SYSCALLS; i++) {
	    profile->train.entry[i] = NULL;
	}

	profile->test = profile->train;
	//pr_err("%s: Got here 3 (new_profile)\n", DEVICE_NAME);

	profile->next = NULL;
	pH_refcount_init(profile, 0);
	
	profile->filename = kmalloc(strlen(filename)+1, GFP_ATOMIC);
	if (profile->filename == NULL) {
		pr_err("%s: Unable to allocate memory for profile->filename in new_profile\n", DEVICE_NAME);
		return -ENOMEM;
	}
	strlcpy(profile->filename, filename, strlen(filename)+1);
	//pr_err("%s: Got here 4 (new_profile)\n", DEVICE_NAME);

	//pH_open_seq_logfile(profile);

	// Add this new profile to the hashtable
	//hash_add(profile_hashtable, &profile->hlist, pid_vnr(task_tgid(current)));
	
	if (!make_temp_profile) {
		// Add this new profile to the llist
		//pr_err("%s: Locking profile list in new_profile on line 460\n", DEVICE_NAME);
		//preempt_disable();
		spin_lock(&pH_profile_list_sem);
		add_to_profile_llist(profile);
		spin_unlock(&pH_profile_list_sem);
		//preempt_enable();
		//pr_err("%s: Unlocking profile list in new_profile on line 462\n", DEVICE_NAME);
		//pr_err("%s: Got here 5 (new_profile) returning...\n", DEVICE_NAME);
	}
	
	//pr_err("%s: Made new profile with filename [%s]\n", DEVICE_NAME, filename);
	
	pH_write_profile(profile);

	return 0;
}

// One issue with this function is if the process_id goes out of use or is reused while the lock
// is held, it might return an incorrect result. Perhaps this is why my code is crashing.
pH_task_struct* llist_retrieve_process(int process_id) {
	pH_task_struct* iterator = NULL;
	
	//pr_err("%s: In llist_retrieve_process\n", DEVICE_NAME);
	
	ASSERT(spin_is_locked(&pH_task_struct_list_sem));
	//ASSERT(!spin_is_locked(&pH_profile_list_sem));
	
	iterator = pH_task_struct_list;
	
	// Checks to see if this function can execute in this instance
	if (!module_inserted_successfully || !pH_aremonitoring) {
		pr_err("%s: ERROR: llist_retrieve_process called before module has been inserted correctly\n", DEVICE_NAME);
		return NULL;
	}
	
	//pr_err("%s: In llist_retrieve_process\n", DEVICE_NAME);

	if (pH_task_struct_list == NULL) {
		return NULL;
	}
	
	do {
		if (iterator->process_id == process_id) {
			//pr_err("%s: Found it! Returning\n", DEVICE_NAME);
			return iterator;
		}
		iterator = iterator->next;
	} while (iterator);
	
	//pr_err("%s: Process %d not found\n", DEVICE_NAME, process_id);
	return NULL;
}

// Initializes a new pH_seq and then adds it to the stack of pH_seqs
int make_and_push_new_pH_seq(pH_task_struct* process) {
	pH_profile* profile = NULL;
	pH_seq* new_sequence = NULL;
	
	ASSERT(process != NULL);
	
	pr_err("%s: In make_and_push_new_pH_seq\n", DEVICE_NAME);
	
	profile = process->profile;
	if (profile != NULL) pH_refcount_inc(profile);
	
	// Checks for NULL profile - do not change this to an assert
	if (!profile || profile == NULL) {
		pr_err("%s: profile is NULL in make_and_push_new_pH_seq\n", DEVICE_NAME);
		return -1;
	}
	
	// Allocates space for the new pH_seq
	new_sequence = kmalloc(sizeof(pH_seq), GFP_ATOMIC);
	if (!new_sequence || new_sequence == NULL) {
		pr_err("%s: Unable to allocate space for new_sequence in make_and_push_new_pH_seq\n", DEVICE_NAME);
		pH_refcount_dec(profile);
		return -ENOMEM;
	}
	
	// Initialize the new pH_seq and push it onto the stack
	new_sequence->next = NULL;
	new_sequence->length = profile->length;
	new_sequence->last = profile->length - 1;
	process->seq = new_sequence;
	pH_refcount_dec(profile);
	pr_err("%s: Exiting make_and_push_new_pH_seq\n", DEVICE_NAME);
	return 0;
}

// Retruns the task_struct of the userspace app
struct task_struct* get_userspace_task_struct(void) {
	ASSERT(have_userspace_pid);
	
	return pid_task(find_pid_ns(userspace_pid, &init_pid_ns), PIDTYPE_PID);
}

int send_signal_to_userspace(int signal_to_send) {
	int ret;
	struct task_struct* t;
	
	t = get_userspace_task_struct();
	if (!t) {
		pr_err("%s: No such PID", DEVICE_NAME);
		return -ESRCH;
	}
	
	ret = send_sig(signal_to_send, t, SIGNAL_PRIVILEGE);
	if (ret < 0) {
		pr_err("%s: Unable to send signal\n", DEVICE_NAME);
		return ret;
	}
	
	/*
	// Switch statement to help with printing out signal sent to userspace
	char signal_sent[8];
	switch (signal_to_send) {
		case SIGSTOP:
			strlcpy(signal_sent, "SIGSTOP", 7);
			break;
		case SIGCONT:
			strlcpy(signal_sent, "SIGCONT", 7);
			break;
		case SIGTERM:
			strlcpy(signal_sent, "SIGTERM", 7);
			break;
		case SIGKILL:
			strlcpy(signal_sent, "SIGKILL", 7);
			break;
		default:
			pr_err("%s: %d signal sent to user space process", DEVICE_NAME, signal_to_send);
			return 0;
	}

	//pr_err("%s: %s signal sent to user space process", DEVICE_NAME, signal_sent);
	*/
	return 0;
}

// Function prototypes for process_syscall
inline void pH_append_call(pH_seq*, int);
inline void pH_train(pH_task_struct*);
//void stack_print(pH_task_struct*);
void free_pH_task_struct(pH_task_struct*);

// Processes a system call
int process_syscall(long syscall) {
	pH_task_struct* process = NULL;
	pH_profile* profile = NULL;
	int ret = -1;
	
	// Boolean checks
	if (!module_inserted_successfully) return 0;
	
	if (!pH_aremonitoring) return 0;
	
	if (!pH_task_struct_list || pH_task_struct_list == NULL) return 0;

	//pr_err("%s: In process_syscall\n", DEVICE_NAME);
	
	// Check to see if a process went out of use
	//clean_processes(); // Temporarily commented out since the module isn't working at the moment
	
	// Retrieve process
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	if (!process) {
		// Ignore this syscall
		ret = 0;
		goto exit_before_profile;
	}
	//pr_err("%s: syscall=%d\n", DEVICE_NAME, syscall);
	//pr_err("%s: Retrieved process successfully\n", DEVICE_NAME);
	//pr_err("\n\n\n\n\n\n\n\%s: No really, the process was retrieved successfully\n*****************\n*****************\n*****************\n", DEVICE_NAME);
	
	if (spin_is_locked(&(process->lock))) {
		spin_lock(&(process->lock));
		spin_unlock(&(process->lock));
	}
	
	profile = process->profile; // Store process->profile in profile for shorter reference
	//pr_err("%s: Looked at the profile\n", DEVICE_NAME);
	
	if (!profile || profile == NULL) {
		pr_err("%s: pH_task_struct corrupted: No profile\n", DEVICE_NAME);
		ASSERT(profile != NULL);
		ret = 1;
		goto exit_before_profile;
	}
	/*
	if (profile->filename == NULL) {
		pr_err("%s: profile is corrupted in process_syscall: NULL profile->filename\n", DEVICE_NAME);
		//pr_err("%s: Quitting early in process_syscall\n", DEVICE_NAME);
		//module_inserted_successfully = FALSE;
		return -1;
	}
	*/
	//pr_err("%s: Retrieved profile successfully\n", DEVICE_NAME);
	
	// Check to see if this profile is still in use
	if (!pH_profile_in_use(profile) || !(profile->lock) || profile->lock == NULL) {
		if (!pH_profile_in_use(profile)) {
			pr_err("%s: profile is not in use in process_syscall\n", DEVICE_NAME);
		}
		if (profile->lock == NULL) {
			pr_err("%s: profile->lock is NULL in process_syscall\n", DEVICE_NAME);
		}
		//vfree(profile); // Don't bother freeing, since this is the only remaining pointer
		//profile = NULL;
		ret = -1;
		goto exit_before_profile;
	}
	
	pH_refcount_inc(profile);
	//pr_err("%s: Incremented the profile's refcount\n", DEVICE_NAME);
	//pr_err("%s: Locking profile->lock\n", DEVICE_NAME);
	spin_lock(profile->lock); // Grabs the lock to this profile
	
	if (profile->lock == NULL) {
		pr_err("%s: ERROR: Somehow the profile->lock was NULL anyway\n", DEVICE_NAME);
		ret = -1;
		goto exit;
	}
	
	if (profile == NULL || !pH_profile_in_use(profile)) {
		spin_unlock(profile->lock);
		ret = -1;
		goto exit;
	}
	
	if (process && (process->seq) == NULL) {
		pH_seq* temp = (pH_seq*) kmalloc(sizeof(pH_seq), GFP_ATOMIC);
		if (!temp) {
			pr_err("%s: Unable to allocate memory for temp in process_syscall\n", DEVICE_NAME);
			if (profile->lock == NULL) {
				ret = -1;
				goto exit;
			}
			spin_unlock(profile->lock);
			ret = -ENOMEM;
			goto exit;
		}

		temp->next = NULL;
		temp->length = profile->length;
		temp->last = profile->length - 1;
		
		pr_err("%s: Got here 1\n", DEVICE_NAME);
		//process->seq = temp;
		//INIT_LIST_HEAD(&temp->seqList);
		if (process) process->seq = temp;
		pr_err("%s: Got here 2\n", DEVICE_NAME);
		INIT_LIST_HEAD(&temp->seqList);
		pr_err("%s: Successfully allocated memory for temp in process_syscall\n", DEVICE_NAME);
	}
	
	if (process) process->count++;
	if (process) pH_append_call(process->seq, syscall);
	//pr_err("%s: Successfully appended call %ld\n", DEVICE_NAME, syscall);
	
	//pr_err("%s: &(profile->count) = %p\n", DEVICE_NAME, &(profile->count));
	profile->count++;
	//pr_err("%s: profile->count = %d\n", DEVICE_NAME, profile->count);
	if (profile->lock == NULL) {
		ret = -1;
		goto exit;
	}
	spin_unlock(profile->lock);
	
	//pr_err("%s: process = %p %d\n", DEVICE_NAME, process, process != NULL);
	///pr_err("%s: profile = %p %d\n", DEVICE_NAME, profile, profile != NULL);
	
	if (process) pH_train(process);
	else {
		pr_err("%s: ERROR: process is NULL\n", DEVICE_NAME);
		ret = -1;
		goto exit;
	}
	//pr_err("%s: Trained process\n", DEVICE_NAME);

	//pr_err("%s: Finished processing syscall %ld\n", DEVICE_NAME, syscall);	
	ret = 0;

exit_before_profile:
	return ret;

exit:
	spin_unlock(profile->lock);
	pH_refcount_dec(profile);
	return ret;
}

// Adds a process to the linked list of processes
void add_process_to_llist(pH_task_struct* t) {
	//pr_err("%s: In add_process_to_llist\n", DEVICE_NAME);

	ASSERT(spin_is_locked(&pH_task_struct_list_sem));
	ASSERT(t != NULL);
	
	if (pH_task_struct_list == NULL) {
		pH_task_struct_list = t;
		t->next = NULL;
		t->prev = NULL;
	}
	else {
		t->next = pH_task_struct_list;
		pH_task_struct_list = t;
		t->prev = NULL;
		t->next->prev = t;
	}
}

// Returns a pH_profile, given a filename
pH_profile* retrieve_pH_profile_by_filename(const char* filename) {
	ASSERT(spin_is_locked(&pH_profile_list_sem));
	
	pH_task_struct* process_list_iterator;
	pH_profile* profile_list_iterator = pH_profile_list;
	
	if (pH_profile_list == NULL) {
		pr_err("%s: pH_profile_list is NULL\n", DEVICE_NAME);
		return NULL;
	}
	//pr_err("%s: pH_profile_list is not NULL\n", DEVICE_NAME);
	
	// Search through profile list
	do {
		//pr_err("%s: Filename is [%s]\n", DEVICE_NAME, profile_list_iterator->filename);
		if (strcmp(filename, profile_list_iterator->filename) == 0) {
			//pr_err("%s: Found it! Returning\n", DEVICE_NAME);
			return profile_list_iterator;
		}
		
		profile_list_iterator = profile_list_iterator->next;
		//pr_err("%s: Iterating\n", DEVICE_NAME);
	} while (profile_list_iterator);
	
	//pr_err("%s: No matching profile was found\n", DEVICE_NAME);
	return NULL;
}

// Handler function for execves
// Since I changed my goto labels to only exit, I must always print the issue before jumping to that
// label
static long jsys_execve(const char __user *filename,
	const char __user *const __user *argv,
	const char __user *const __user *envp)
{
	char* path_to_binary = NULL;
	int current_process_id;
	int list_length;
	pH_task_struct* process = NULL;
	pH_profile* profile = NULL;
	bool already_had_process = FALSE;

	// Boolean checks
	if (!module_inserted_successfully) goto exit;
	
	if (!pH_aremonitoring) goto exit;

	pr_err("%s: In jsys_execve\n", DEVICE_NAME);
	
	current_process_id = pid_vnr(task_tgid(current)); // Grab the process ID right now
	
	//pr_err("%s: List length at start is %d\n", DEVICE_NAME, pH_task_struct_list_length());
	
	//clean_processes();
	//pr_err("%s: Back from clean_processes()\n", DEVICE_NAME);
	
	//pr_err("%s: Calling llist_retrieve_process from jsys_execve\n", DEVICE_NAME);
	//preempt_disable();
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(current_process_id);
	spin_unlock(&pH_task_struct_list_sem);
	//preempt_enable();
	if (!process || process == NULL) {
		//pr_err("%s: Unable to find process in jsys_execve\n", DEVICE_NAME);
		//pr_err("%s: Continuing anyway...\n", DEVICE_NAME);
		
		// Allocate memory for this process
		process = kmalloc(sizeof(pH_task_struct), GFP_ATOMIC);
		if (!process) {
			pr_err("%s: Unable to allocate memory for process\n", DEVICE_NAME);
			goto exit;
		}
		//pr_err("%s: Successfully allocated memory for process\n", DEVICE_NAME);
		
		// Initialization for entirely new process - this might not be quite correct
		spin_lock_init(&(process->lock));
		process->process_id = current_process_id;
		process->task_struct = current;
		process->pid = task_pid(current);
		process->profile = NULL;
		process->next = NULL;
		process->prev = NULL;
		process->seq = NULL;
		//pr_err("%s: Pre-initialized entirely new process\n", DEVICE_NAME);
	}
	else {
		already_had_process = TRUE;
		pH_refcount_dec(process->profile);
		pr_err("%s: Decremented old profile refcount\n", DEVICE_NAME);
	}
	
	// Allocate space for path_to_binary
	path_to_binary = kmalloc(sizeof(char) * 4000, GFP_ATOMIC);
	if (!path_to_binary) {
		pr_err("%s: Unable to allocate memory for path_to_binary\n", DEVICE_NAME);
		goto exit;
	}
	//pr_err("%s: Successfully allocated memory for path_to_binary\n", DEVICE_NAME);
	
	// Copy memory from userspace to kernel land
	copy_from_user(path_to_binary, filename, sizeof(char) * 4000);
	//pr_err("%s: path_to_binary = [%s]\n", DEVICE_NAME, path_to_binary);
	
	// Checks to see if path_to_binary is okay - perhaps move this to handle_new_process
	if (!path_to_binary || path_to_binary == NULL || strlen(path_to_binary) < 1 || 
		!(*path_to_binary == '~' || *path_to_binary == '.' || *path_to_binary == '/'))
	{
		pr_err("%s: In jsys_execve with corrupted path_to_binary: [%s]\n", DEVICE_NAME, path_to_binary);
		goto corrupted_path_to_binary;
	}
	//pr_err("%s: My code thinks path_to_binary is not corrupted\n", DEVICE_NAME);
	
	/* // Commented out since I'm not using stacks
	// Emtpies stack of pH_seqs
	while (already_had_process && process->seq != NULL) {
		//pr_err("%s: In while %d\n", DEVICE_NAME, i);
		stack_pop(process);
		//pr_err("%s: &process = %p\n", DEVICE_NAME, &process);
		//pr_err("%s: After stack_pop(process);\n", DEVICE_NAME);
	}
	//pr_err("%s: Emptied stack of pH_seqs\n", DEVICE_NAME);
	*/
	
	// Since we are using an existing pH_task_struct, the task_struct, pid, etc. are already
	// initialized - instead we want to wipe everything else
	//pH_reset_ALF(this_process);
	process->seq = NULL;
	//spin_lock_init(&(this_process->pH_seq_stack_sem));
	process->delay = 0;
	process->count = 0;
	//pr_err("%s: Initialized process\n", DEVICE_NAME);
	
	// Grab the profile from memory - if this fails, I would want to do a read, but since I am not
	// implementing that right now, then make a new profile
	//pr_err("%s: Attempting to retrieve profile...\n", DEVICE_NAME);
	//pr_err("%s: Locking profile list in jsys_execve on line 1070\n", DEVICE_NAME);
	//preempt_disable();
	spin_lock(&pH_profile_list_sem);
	profile = retrieve_pH_profile_by_filename(path_to_binary);
	spin_unlock(&pH_profile_list_sem);
	//preempt_enable();
	//pr_err("%s: Unlocking profile list in jsys_execve on line 1072\n", DEVICE_NAME);
	//pr_err("%s: Profile found: %s\n", DEVICE_NAME, profile != NULL ? "yes" : "no");
	
	pr_err("%s: Calling add_to_read_filename_queue from jsys_execve...\n", DEVICE_NAME);
	spin_lock(&read_filename_queue_lock);
	add_to_read_filename_queue(path_to_binary);
	spin_unlock(&read_filename_queue_lock);
	
	/*
	// If there is no corresponding profile, make a new one - this should actually start a read
	// request, once I have got to implementing that
	if (!profile || profile == NULL) {
		profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
		if (!profile) {
			pr_err("%s: Unable to allocate memory for profile in handle_new_process\n", DEVICE_NAME);
			goto exit;
		}
		
		new_profile(profile, path_to_binary, TRUE);
		pr_err("%s: Made new profile for [%s]\n", DEVICE_NAME, path_to_binary);
		
		if (!profile || profile == NULL) {
			pr_err("%s: new_profile() made a corrupted or NULL profile\n", DEVICE_NAME);
		}
	}
	else {
		kfree(path_to_binary);
		path_to_binary = NULL;
	}
	*/
	
	// Yes, the boolean check is quite necessary
	if (profile != NULL) {
		process->profile = profile;
		pH_refcount_inc(profile);
	}
	
	if (!already_had_process) {
		//preempt_disable();
		spin_lock(&pH_task_struct_list_sem);
		add_process_to_llist(process);
		spin_unlock(&pH_task_struct_list_sem);
		//preempt_enable();
		pr_err("%s: process has been added to the llist\n", DEVICE_NAME);
	}
	
	/* // The task struct already exists, what we need to be doing now is decrementing the refcount
	   // for the old profile and then searching for the new profile (also wipe the task struct data).
	   // Double-check all of my execve handlers - I need to do the appropriate things in each handler.
	// Handle the new process
	handle_new_process(path_to_binary, NULL, current_process_id);
	*/
	
	//list_length = pH_task_struct_list_length();
	//pr_err("%s: List length at end is %d\n", DEVICE_NAME, list_length);
	
	//successful_jsys_execves++; // Increment successful_jsys_execves
	
	pr_err("%s: Leaving jsys_execve after successful run\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
	
exit:
	kfree(path_to_binary);
	path_to_binary = NULL;
	if (process != NULL) {
		pr_err("%s: Calling free_pH_task_struct from jsys_execve()\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	process = NULL;
	
	pr_err("%s: Leaving jsys_execve from exit\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
	
corrupted_path_to_binary:
	kfree(path_to_binary);
	path_to_binary = NULL;
	process = NULL;
	
	pr_err("%s: Leaving jsys_execve from corrupted_path_to_binary\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
}

// Struct required for all kretprobe structs
struct my_kretprobe_data {
	ktime_t entry_stamp;
};

static int sys_execve_return_handler(struct kretprobe_instance* ri, struct pt_regs* regs) {
	int ret = -1;
	int process_id;
	int temp;
	pH_task_struct* process = NULL;
	pH_profile* profile = NULL;
	task_struct_wrapper* to_add = NULL;
	const char* temp_string = NULL;
	
	if (!module_inserted_successfully) return 0;
	
	pr_err("%s: In sys_execve_return_handler\n", DEVICE_NAME);
	
	process_id = pid_vnr(task_tgid(current));
	
	ret = send_sig(SIGSTOP, current, SIGNAL_PRIVILEGE);
	if (ret < 0) {
		pr_err("%s: Failed to send SIGSTOP signal to %d\n", DEVICE_NAME, process_id);
		pr_err("%s: Leaving sys_execve_return_handler...\n", DEVICE_NAME);
		return ret;
	}
	pr_err("%s: Sent SIGSTOP signal to %d\n", DEVICE_NAME, process_id);
	
	to_add = kmalloc(sizeof(task_struct_wrapper), GFP_ATOMIC);
	if (to_add == NULL) {
		pr_err("%s: Failed to allocate memory for to_add in sys_execve_return_handler\n", DEVICE_NAME);
		ret = -ENOMEM;
		goto only_continue_process;
	}
	to_add->task_struct = current;
	
	spin_lock(&task_struct_queue_lock);
	add_to_task_struct_queue(to_add);
	spin_unlock(&task_struct_queue_lock);
	
	/*
	spin_lock(&read_filename_queue_lock);
	remove_from_read_filename_queue();
	spin_unlock(&read_filename_queue_lock);
	*/
	
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(process_id);
	spin_unlock(&pH_task_struct_list_sem);
	
	if (!process || process == NULL) {
		pr_err("%s: No matching process\n", DEVICE_NAME);
		ret = -1;
		spin_lock(&task_struct_queue_lock);
		remove_from_task_struct_queue();
		spin_unlock(&task_struct_queue_lock);
		goto only_continue_process;
	}
	
	profile = process->profile;
	
	if (!profile || profile == NULL) {
		profile = __vmalloc(sizeof(pH_profile), GFP_ATOMIC, PAGE_KERNEL);
		if (!profile) {
			pr_err("%s: Unable to allocate memory for profile in sys_execve_return_handler\n", DEVICE_NAME);
			ret = -ENOMEM;
			spin_lock(&task_struct_queue_lock);
			remove_from_task_struct_queue();
			spin_unlock(&task_struct_queue_lock);
			goto only_continue_process;
		}
		
		spin_lock(&read_filename_queue_lock);
		temp_string = peek_read_filename_queue();
		spin_unlock(&read_filename_queue_lock);
		
		new_profile(profile, temp_string, TRUE);
		pr_err("%s: Made new profile for [%s]\n", DEVICE_NAME, temp_string);
		temp_string = NULL;
		
		spin_lock(&read_filename_queue_lock);
		remove_from_read_filename_queue();
		spin_unlock(&read_filename_queue_lock);
		
		if (!profile || profile == NULL) {
			pr_err("%s: new_profile() made a corrupted or NULL profile\n", DEVICE_NAME);
			ASSERT(profile != NULL);
			ret = -1;
			spin_lock(&task_struct_queue_lock);
			remove_from_task_struct_queue();
			spin_unlock(&task_struct_queue_lock);
			goto only_continue_process;
		}
		
		process->profile = profile;
		pH_refcount_inc(process->profile);
	}
	
	spin_unlock(&(process->lock));
	process_syscall(59);

	peek_task_struct_queue();

	spin_lock(&task_struct_queue_lock);
	remove_from_task_struct_queue();
	spin_unlock(&task_struct_queue_lock);

	ret = send_sig(SIGCONT, current, SIGNAL_PRIVILEGE);
	if (ret < 0) {
		pr_err("%s: Failed to send SIGCONT signal to %d\n", DEVICE_NAME, process_id);
		pr_err("%s: Leaving sys_execve_return_handler...\n", DEVICE_NAME);
		return ret;
	}
	pr_err("%s: Sent SIGCONT signal to %d\n", DEVICE_NAME, process_id);
	
	pr_err("%s: Leaving sys_execve_return_handler...\n", DEVICE_NAME);
	return 0;
	
only_continue_process:
	temp = send_sig(SIGCONT, current, SIGNAL_PRIVILEGE);
	if (temp < 0) {
		pr_err("%s: Failed to send SIGCONT signal to %d\n", DEVICE_NAME, process_id);
		pr_err("%s: Leaving sys_execve_return_handler...\n", DEVICE_NAME);
		if (process != NULL) spin_unlock(&(process->lock));
		return ret;
	}
	pr_err("%s: Sent SIGCONT signal to %d\n", DEVICE_NAME, process_id);
	
	pr_err("%s: Leaving sys_execve_return_handler...\n", DEVICE_NAME);
	if (process != NULL) spin_unlock(&(process->lock));
	return ret;
}

static struct kretprobe sys_execve_kretprobe = {
	.handler = sys_execve_return_handler,
	.data_size = sizeof(struct my_kretprobe_data),
	.maxactive = 20,
};

// Frees profile storage
void pH_free_profile_storage(pH_profile *profile)
{   
    int i;
    
    ASSERT(profile != NULL);
    ASSERT(!pH_profile_in_use(profile));

	//pr_err("%s: In pH_free_profile_storage for %d\n", DEVICE_NAME, profile->identifier);

	// Free profile->filename
    kfree(profile->filename);
    profile->filename = NULL;
    pr_err("%s: Freed profile->filename\n", DEVICE_NAME);
    
    // Free entries
    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
        if (profile->train.entry[i]) {
        	kfree(profile->train.entry[i]);
        	profile->train.entry[i] = NULL;
        }
        if (profile->test.entry[i]) {
        	kfree(profile->test.entry[i]);
        	profile->test.entry[i] = NULL;
        }
    }
    
    //pr_err("%s: Exiting pH_free_profile_storage\n", DEVICE_NAME);
}

// Returns 0 on success and anything else on failure
// Calling functions (currently only pH_free_profile) MUST handle returned errors if possible
// Currently does not hold any locks, and therefore calling functions must lock appropriately
int pH_remove_profile_from_list(pH_profile *profile)
{
    pH_profile *prev_profile, *cur_profile;
    
    ASSERT(spin_is_locked(&pH_profile_list_sem));
    ASSERT(profile != NULL);
	ASSERT(!pH_profile_in_use(profile));

    //pr_err("%s: In pH_remove_profile_from_list for %d\n", DEVICE_NAME, profile->identifier);
    
    if (pH_profile_list == profile) {
            pH_profile_list = profile->next;
            return 0;
    } else if (pH_profile_list == NULL) {
            err("pH_profile_list is NULL when trying to free profile %s",
                profile->filename);
            return -1;
    } else {
            prev_profile = pH_profile_list;
            cur_profile = prev_profile->next;
            while ((cur_profile != profile) && (cur_profile != NULL)) {
                    prev_profile = cur_profile;
                    cur_profile = prev_profile->next;
            }
            if (cur_profile == profile) {
                    prev_profile->next = cur_profile->next;
                    return 0;
            } else {
                    err("while freeing, couldn't find profile %s in "
                        "pH_profile_list", profile->filename);
                    return -1;
            }
    }
}

// Destructor for pH_profiles - perhaps remove use of freeing lock?
void pH_free_profile(pH_profile *profile)
{
    int ret;
    
    ASSERT(profile != NULL);
	ASSERT(!pH_profile_in_use(profile));
    
    //pr_err("%s: In pH_free_profile for %d\n", DEVICE_NAME, profile->identifier);
    
    //spin_lock(&(profile->freeing_lock));
    
    if (profile->lock == NULL) {
    	return;
    }
    
    // Deals with nasty locking stuff
    spin_lock(profile->lock);
    if (profile == NULL || !pH_profile_in_use(profile)) {
    	spin_unlock(profile->lock);
    	return;
    }
    /*
    if (spin_trylock(&pH_profile_list_sem) == 0) {
    	if (profile->lock == NULL) {
			return;
		}
    	spin_unlock(profile->lock);
    	spin_lock(&pH_profile_list_sem);
    	spin_lock(profile->lock);
    	if (profile == NULL || !pH_profile_in_use(profile)) {
			spin_unlock(profile->lock);
			return;
		}
    }
    */
    
    ret = pH_remove_profile_from_list(profile);
    //spin_unlock(&pH_profile_list_sem);
    
    ASSERT(ret != 0);

    if (pH_aremonitoring) {
        //pH_write_profile(profile);
    }

    pH_free_profile_storage(profile);
    if (profile->lock != NULL) spin_unlock(profile->lock);
    //pr_err("%s: Back in pH_free_profile after pH_free_profile_storage\n", DEVICE_NAME);
    //kfree(profile->lock); // Do not do this - the profile lock cannot come out from under another functions feet
    //profile->lock = NULL; // Instead, check to see if the profile is still around
    //pr_err("%s: Freed profile->lock\n", DEVICE_NAME);
    //spin_unlock(&(profile->freeing_lock));
    //vfree(profile); // For now, don't free any profiles
    //profile = NULL; // This is okay, because profile was removed from the linked list above
    //pr_err("%s: Freed pH_profile (end of function)\n", DEVICE_NAME);
}

// Removes a process from the list of processes
int remove_process_from_llist(pH_task_struct* process) {
	pH_task_struct *prev_task_struct, *cur_task_struct;
	
	ASSERT(spin_is_locked(&pH_task_struct_list_sem));
	ASSERT(process != NULL);
	
	//pr_err("%s: In remove_process_from_llist\n", DEVICE_NAME);

	if (pH_task_struct_list == NULL) {
		err("pH_task_struct_list is empty (NULL) when trying to free process %ld", process->process_id);
		return -1;
	}
	else if (pH_task_struct_list == process) {
		//pr_err("%s: pH_task_struct_list == process\n", DEVICE_NAME);
		pH_task_struct_list = pH_task_struct_list->next;
		//pr_err("%s: Got here 1\n", DEVICE_NAME);
		if (pH_task_struct_list != NULL) {
			pH_task_struct_list->prev = NULL;
			//pr_err("%s: Got here 2\n", DEVICE_NAME);
			if (pH_task_struct_list->next != NULL) {
				pH_task_struct_list->next->prev = pH_task_struct_list;
			}
		}
		//pr_err("%s: Returning from remove_process_from_llist\n", DEVICE_NAME);
		return 0;
	}
	else {
		//pr_err("%s: In else of remove_process_from_llist\n", DEVICE_NAME);
		prev_task_struct = pH_task_struct_list;
		cur_task_struct = pH_task_struct_list->next;
		while (cur_task_struct != NULL) {
			if (cur_task_struct == process) {
				//pr_err("%s: cur_task_struct == process\n", DEVICE_NAME);
				prev_task_struct->next = process->next;
				if (prev_task_struct->next != NULL) {
					prev_task_struct->next->prev = prev_task_struct;
				}
				//spin_unlock(&pH_task_struct_list_sem);
				return 0;
			}
			
			prev_task_struct = cur_task_struct;
			cur_task_struct = cur_task_struct->next;
		}
		
		err("While freeing, couldn't find process %ld in pH_task_struct_list", process->process_id);
		return -1;
	}
}

// Destructor for pH_task_structs
void free_pH_task_struct(pH_task_struct* process) {
	pH_profile* profile = NULL;
	int i = 0;
	int ret;
	
	ASSERT(process != NULL);

	pr_err("%s: In free_pH_task_struct for %ld %s\n", DEVICE_NAME, process->process_id, process->profile->filename);
	//pr_err("%s: process = %p\n", DEVICE_NAME, process);
	//pr_err("%s: process->seq = %p\n", DEVICE_NAME, process->seq); // This will only print NULL if this process did not make a single syscall
	
	// Remove from the linked list right away, and check return value
	spin_lock(&pH_task_struct_list_sem);
	ret = remove_process_from_llist(process);
	spin_unlock(&pH_task_struct_list_sem);
	
	if (ret != 0) {
		pr_err("%s: remove_process_from_llist failed with %d\n", DEVICE_NAME, ret);
		return;
	}
	
	if (pH_aremonitoring) {
		//stack_print(process);
	}
	
	/* // Commented out since I'm not using stacks
	// Emtpies stack of pH_seqs
	while (process->seq != NULL) {
		//pr_err("%s: In while %d\n", DEVICE_NAME, i);
		stack_pop(process);
		//pr_err("%s: &process = %p\n", DEVICE_NAME, &process);
		//pr_err("%s: After stack_pop(process);\n", DEVICE_NAME);
		i++;
	}
	pr_err("%s: Emptied stack of pH_seqs\n", DEVICE_NAME);
	*/
	
	//free_syscalls(process); // Frees syscalls
	//pr_err("%s: Freed syscalls\n", DEVICE_NAME);
	
	/* // For now, don't free any profiles - later, implement freeing profiles every ten seconds
	   // (every ten seconds userspace should send a "free profiles" message, where the profile list
	   // should be locked so that no profiles can be added or removed until they are all freed)
	// This boolean test is required for when this function is called when the module is being removed
	//if (module_inserted_successfully) {
		profile = process->profile;

		if (profile != NULL) {
			pH_refcount_dec(profile);

			if (!pH_profile_in_use(profile)) {
				// Free profile
				pH_free_profile(profile);
				profile = NULL; // Okay because the profile is removed from llist in pH_free_profile
				pr_err("%s: Freed profile\n", DEVICE_NAME);
			}
		}
		else {
			pr_err("%s: ERROR: Corrupt process in free_pH_task_struct: No profile\n", DEVICE_NAME);
			ASSERT(profile != NULL);
			return;
		}
	//}
	*/
	
	// When everything else is done, kfree process
	kfree(process);
	process = NULL; // Okay because process is removed from llist above
	pr_err("%s: Freed process (end of function)\n", DEVICE_NAME);
}

noinline static long jsys_exit(int error_code) {
	pH_task_struct* process = NULL;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	pr_err("%s: In jsys_exit for %d\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	
	if (process == NULL) goto not_monitoring;
	
	pr_err("%s: In jsys_exit for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(current)), process->profile->filename);
	
	//process_syscall(72); // Process this syscall before calling free_pH_task_struct on process
	//pr_err("%s: Back in jsys_exit after processing syscall\n", DEVICE_NAME);
	
	pr_err("%s: Calling free_pH_task_struct from jsys_exit\n", DEVICE_NAME);
	free_pH_task_struct(process);
	
	pr_err("%s: Leaving jsys_exit...\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
	
not_monitoring:
	pr_err("%s: %d had no pH_task_struct associated with it\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	jprobe_return();
	return 0;
	
not_inserted:
	pr_err("%s: Leaving jsys_exit from not_inserted...\n", DEVICE_NAME);
	jprobe_return();
	return 0;
}

struct jprobe sys_exit_jprobe = {
	.entry = jsys_exit,
};

noinline static long jdo_group_exit(int error_code) {
	pH_task_struct* process = NULL;
	struct task_struct* p = NULL;
	struct task_struct* t = NULL;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	p = current;
	
	pr_err("%s: In jdo_group_exit for %d\n", DEVICE_NAME, pid_vnr(task_tgid(p)));
	
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);

	if (process == NULL) goto not_monitoring;
	
	pr_err("%s: In jdo_group_exit for %d %s\n", DEVICE_NAME, pid_vnr(task_tgid(p)), process->profile->filename);
	
	t = p;
	while_each_thread(p, t) {
		if (t->exit_state) continue;
		
		spin_lock(&pH_task_struct_list_sem);
		process = llist_retrieve_process(pid_vnr(task_tgid(current)));
		spin_unlock(&pH_task_struct_list_sem);
		
		if (process != NULL) {
			pr_err("%s: Calling free_pH_task_struct from jdo_group_exit\n", DEVICE_NAME);
			free_pH_task_struct(process);
		}
	}
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	
	if (process != NULL) {
		pr_err("%s: Calling free_pH_task_struct from jdo_group_exit\n", DEVICE_NAME);
		free_pH_task_struct(process);
	}
	
	pr_err("%s: Returning from jdo_group_exit...\n", DEVICE_NAME);
	
	jprobe_return();
	return 0;
	
not_monitoring:
	pr_err("%s: %d had no pH_task_struct associated with it\n", DEVICE_NAME, pid_vnr(task_tgid(current)));
	jprobe_return();
	return 0;
	
not_inserted:
	pr_err("%s: Returning from jdo_group_exit not_inserted\n", DEVICE_NAME);
	jprobe_return();
	return 0;
}

struct jprobe do_group_exit_jprobe = {
	.entry = jdo_group_exit,
};

noinline static void jfree_pid(struct pid* pid) {
	pH_task_struct* iterator = NULL;
	int i = 0;
	bool freed_anything = FALSE;
	
	if (!module_inserted_successfully) goto exit;
	
	pr_err("%s: In jfree_pid\n", DEVICE_NAME);
	
	spin_lock(&pH_task_struct_list_sem);
	for (iterator = pH_task_struct_list; iterator != NULL; iterator = iterator->next) {
		if (i > 10000) {
			pr_err("%s: ERROR: Got stuck in jfree_pid for loop\n", DEVICE_NAME);
			spin_unlock(&pH_task_struct_list_sem);
			ASSERT(i <= 10000);
			goto exit;
		}
		if (iterator->pid == pid) {
			spin_unlock(&pH_task_struct_list_sem);
			pr_err("%s: Calling free_pH_task_struct from jfree_pid\n", DEVICE_NAME);
			free_pH_task_struct(iterator);
			iterator = NULL;
			freed_anything = TRUE;
			//pr_err("%s: Done in jfree_pid\n", DEVICE_NAME);
			goto exit;
			
			/* // This used to be for freeing more than one process at a time, which may not be necessary
			pr_err("%s: Got here 1\n", DEVICE_NAME);
			if (iterator == pH_task_struct_list) {
				pr_err("%s: Got here 2\n", DEVICE_NAME);
				free_pH_task_struct(iterator);
				pr_err("%s: Got here 3\n", DEVICE_NAME);
				iterator = pH_task_struct_list;
				pr_err("%s: Got here 4\n", DEVICE_NAME);
				if (iterator == NULL) {
					spin_unlock(&pH_task_struct_list_sem);
					goto exit;
				}
			}
			else {
				pr_err("%s: Got here 5\n", DEVICE_NAME);
				iterator = iterator->prev;
				pr_err("%s: Got here 6\n", DEVICE_NAME);
				free_pH_task_struct(iterator->next);
				pr_err("%s: Got here 7\n", DEVICE_NAME);
			}
			*/
		}
		i++;
	}
	spin_unlock(&pH_task_struct_list_sem);
	
	ASSERT(freed_anything);
	
	pr_err("%s: Returning from successful jfree_pid...\n", DEVICE_NAME);
	
	jprobe_return();
	return;

exit:
	pr_err("%s: Returning from jfree_pid exit...\n", DEVICE_NAME);
	jprobe_return();
	return;
}

struct jprobe free_pid_jprobe = {
	.entry = jfree_pid,
};

// This is for when a process receives a signal, NOT for when it resumes execution following
// the signal. I will need to implement a second jprobe handler for resuming execution.
noinline static void jhandle_signal(struct ksignal* ksig, struct pt_regs* regs) {
	pH_task_struct* process = NULL;
	
	if (!module_inserted_successfully) goto not_inserted;
	
	pr_err("%s: In jhandle_signal\n", DEVICE_NAME);
	
	// Will this retrieve the process that the signal is being sent to, or will it retrieve the
	// process that is sending the signal?
	spin_lock(&pH_task_struct_list_sem);
	process = llist_retrieve_process(pid_vnr(task_tgid(current)));
	spin_unlock(&pH_task_struct_list_sem);
	
	if (process != NULL) {
		pr_err("%s: Calling make_and_push_new_pH_seq from jhandle_signal...\n", DEVICE_NAME);
		make_and_push_new_pH_seq(process);
		pr_err("%s: Back in jhandle_signal after make_and_push_new_pH_seq\n", DEVICE_NAME);
	}
	
	pr_err("%s: Returning from successful jhandle_signal...\n", DEVICE_NAME);
	jprobe_return();
	return;
	
not_inserted:
	pr_err("%s: Returning from jhandle_signal not_inserted...\n", DEVICE_NAME);
	jprobe_return();
	return;
}

// Frees all of the pH_task_structs in one go
int free_pH_task_structs(void) {
	int ret = 0;
	
	while (pH_task_struct_list != NULL) {
		free_pH_task_struct(pH_task_struct_list);
		ret++;
	}
	
	return ret;
}

// Function responsible for module insertion
static int __init ebbchar_init(void) {
	int ret, i, j;
	
	pr_info("%s: Initializing the EBBChar LKM\n", DEVICE_NAME);

	// Try to dynamically allocate a major number for the device
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber < 0) {
		pr_err("%s: Failed to register a major number\n", DEVICE_NAME);
		return majorNumber;
	}
	pr_err("%s: registered correctly with major number %d\n", DEVICE_NAME, majorNumber);

	// Register the device class
	ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(ebbcharClass)) {           // Check for error and clean up if there is
		pr_err("%s: Failed to register device class\n", DEVICE_NAME);
		goto failed_class_create;
	}
	pr_err("%s: device class registered correctly\n", DEVICE_NAME);

	// Register the device driver
	ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(ebbcharDevice)) {          // Clean up if there is an error
		pr_err("%s: Failed to create the device\n", DEVICE_NAME);
		goto failed_device_create;
	}
	pr_err("%s: device class created correctly\n", DEVICE_NAME); // Device was initialized
	mutex_init(&ebbchar_mutex); // Initialize the mutex dynamically
	
	do_group_exit_jprobe.kp.addr = kallsyms_lookup_name("do_group_exit");
	ret = register_jprobe(&do_group_exit_jprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register do_group_exit_jprobe, returned %d\n", DEVICE_NAME, ret);
		
		//unregister_jprobe(&handle_signal_jprobe);
		//unregister_jprobe(&sys_sigreturn_jprobe);
		//unregister_jprobe(&do_signal_jprobe);
		//unregister_kretprobe(&fork_kretprobe);
		
		goto failed_kprobe_registration;
	}
	pr_err("%s: Registered do_group_exit_jprobe\n", DEVICE_NAME);
	
	sys_execve_kretprobe.kp.addr = kallsyms_lookup_name("sys_execve");
	ret = register_kretprobe(&sys_execve_kretprobe);
	if (ret < 0) {
		pr_err("%s: Failed to register sys_execve_kretprobe, returned %d\n", DEVICE_NAME, ret);
		goto failed_kprobe_registration;
	}
	
	//pr_err("%s: num_syscalls = %d\n", DEVICE_NAME, num_syscalls);
	pr_err("%s: Registering syscall jprobes...\n", DEVICE_NAME);
	for (i = 0; i < num_syscalls; i++) {
		ret = register_jprobe(&jprobes_array[i]);
		if (ret < 0) {
			pr_err("%s: register_jprobe failed (%s), returned %d\n", DEVICE_NAME, jprobes_array[i].kp.symbol_name, ret);
			
			//unregister_jprobe(&handle_signal_jprobe);
			//unregister_jprobe(&sys_sigreturn_jprobe);
			//unregister_jprobe(&do_signal_jprobe);
			//unregister_kretprobe(&fork_kretprobe);
			//unregister_kretprobe(&exit_kretprobe);
			
			// Should it be j <= i?
			for (j = 0; j < i; j++) {
				unregister_jprobe(&jprobes_array[j]);
			}
			
			goto failed_kprobe_registration;
		}
		//pr_err("%s: %d: Successfully registered %s\n", DEVICE_NAME, i, jprobes_array[i].kp.symbol_name);
	}
	pr_err("%s: Registered all syscall probes\n", DEVICE_NAME);
	
	spin_lock_init(&read_filename_queue_lock);
	spin_lock_init(&task_struct_queue_lock);
	
	pr_err("%s: Successfully initialized %s\n", DEVICE_NAME, DEVICE_NAME);
	
	// Set booleans accordingly, now that initialization is complete
	module_inserted_successfully = TRUE;
	pH_aremonitoring = 1;

	return 0;

failed_kprobe_registration:
	mutex_destroy(&ebbchar_mutex);
failed_device_create:
	class_unregister(ebbcharClass);
	class_destroy(ebbcharClass);
failed_class_create:
	unregister_chrdev(majorNumber, DEVICE_NAME);
	return PTR_ERR(ebbcharDevice);
}

// Perhaps the best way to remove the module is just to reboot?
static void __exit ebbchar_exit(void){
	int i, profiles_freed, pH_task_structs_freed;
	
	// Set all booleans accordingly - this should be the first thing you do to prevent any more code
	// from running
	pH_aremonitoring = 0;
	module_inserted_successfully = FALSE;

	pr_err("%s: Exiting...\n", DEVICE_NAME);

	//print_llist(); // For now, don't bother with printing the llist
	
	//unregister_jprobe(&handle_signal_jprobe);
	//unregister_jprobe(&sys_sigreturn_jprobe);
	//unregister_jprobe(&do_signal_jprobe);
	
	/* // Temporarily commented out to debug this function
	// Unregister jprobes - it seems this was working just fine before, but Anil said its okay
	// if I don't bother with unregistering them
	for (i = 0; i < num_syscalls; i++) {
		unregister_jprobe(&jprobes_array[i]);
	}
	pr_err("%s: Unregistered syscall jprobes\n", DEVICE_NAME);
	*/

	/*
	// Unregister fork_kretprobe
	unregister_kretprobe(&fork_kretprobe);
	pr_err("%s: Missed probing %d instances of fork\n", DEVICE_NAME, fork_kretprobe.nmissed);
	*/
	
	/*
	// Unregister exit_kretprobe
	unregister_kretprobe(&exit_kretprobe);
	pr_err("%s: Missed probing %d instances of exit\n", DEVICE_NAME, exit_kretprobe.nmissed);
	*/
	
	//profiles_freed = pH_profile_list_length();
	
	//pr_err("%s: Freeing profiles...\n", DEVICE_NAME);
	//profiles_freed = free_profiles();
	pr_err("%s: Freeing pH_task_structs...\n", DEVICE_NAME);
	pH_task_structs_freed = free_pH_task_structs();
	
	// Miscellaneous cleanup
	mutex_destroy(&ebbchar_mutex);
	device_destroy(ebbcharClass, MKDEV(majorNumber, 0));
	class_unregister(ebbcharClass);
	class_destroy(ebbcharClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	
	// Print lengths of lists - can't print everything until I add pH_profile_list_length() back
	//pr_err("%s: At time of module removal, pH was monitoring %d processes and had %d profiles in memory\n", DEVICE_NAME, pH_task_structs_freed, profiles_freed);
	pr_err("%s: During the uptime of the module, %d profiles were created\n", DEVICE_NAME, profiles_created);
	pr_err("%s: During the uptime of the module, there were %d successful jsys_execves\n", DEVICE_NAME, successful_jsys_execves);
	
	pr_err("%s: %s successfully removed\n", DEVICE_NAME, DEVICE_NAME);
}

static int dev_open(struct inode *inodep, struct file *filep) {
	if (!mutex_trylock(&ebbchar_mutex)) {
		pr_err("%s: Device in use by another process\n", DEVICE_NAME);
		return -EBUSY;
	}
	
	output_string = kmalloc(sizeof(char) * 254, GFP_ATOMIC);
	if (!output_string) {
		pr_err("%s: Unable to allocate memory for output_string", DEVICE_NAME);
		return -EFAULT;
	}
	
	bin_receive_ptr = vmalloc(sizeof(pH_disk_profile));
	if (!bin_receive_ptr) {
		pr_err("%s: Unable to allocate memory for bin_receive_ptr", DEVICE_NAME);
		return -EFAULT;
	}
	
	numberOpens++;
	pr_err("%s: Device has been opened %d time(s)\n", DEVICE_NAME, numberOpens);
	return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset) {
	int bytes_not_copied;
	
	bytes_not_copied = copy_to_user(buffer, "ignore", 7);
	if (bytes_not_copied > 0) return -EFAULT;
	
	return bytes_not_copied;
}

static ssize_t dev_write(struct file *filep, const char *buf, size_t len, loff_t *offset) {
	char* buffer = NULL;
	int ret;
	
	user_process_has_been_loaded = TRUE;
	binary_read = FALSE;
	
	if (numberOpens <= 0) return -EFAULT;
	
	buffer = kmalloc(sizeof(char) * 254, GFP_ATOMIC);
	if (!buffer) {
		pr_err("%s: Unable to allocate memory for dev_write buffer", DEVICE_NAME);
		return len;
	}
	
	copy_from_user(buffer, buf, sizeof(char) * 254); // Perhaps I should check how much got across?
	//pr_err("%s: Did some setup\n", DEVICE_NAME);
	
	// If we failed to receive a message, kill the userspace app and return -1
	if (buffer == NULL || strlen(buffer) < 1) {
        pr_err("%s: Failed to read the message from userspace.%d%d\n", DEVICE_NAME, buffer == NULL, strlen(buffer) < 1);
        
        if (send_signal_to_userspace(SIGTERM) < 0) send_signal_to_userspace(SIGKILL);
        
        pr_err("%s: Userspace process killed\n", DEVICE_NAME);
        
        return -1;
    }
    
    //pr_err("%s: Received message [%s] from userspace app\n", DEVICE_NAME, buffer);
	
	// If you do not have the userspace pid, then you must be getting it right now
	if (!have_userspace_pid) {
		// Convert the string buffer to a long and store it in userspace_pid
		kstrtol(buffer, 10, &userspace_pid);
		have_userspace_pid = TRUE;
		//pr_err("%s: Received %ld PID from userspace\n", DEVICE_NAME, userspace_pid);
	}
	
	// Start of temp code for early exit -----------------------
	
	// Send SIGSTOP signal to the userspace app
	ret = send_signal_to_userspace(SIGSTOP);
	if (ret < 0) return ret;

	// We are done waiting for the user now
	done_waiting_for_user = TRUE;
	return 0;
	
	// End of temp code for early exit -------------------------
}

static int dev_release(struct inode *inodep, struct file *filep) {
	module_inserted_successfully = FALSE;
	pH_aremonitoring             = 0;
	done_waiting_for_user        = FALSE;
	have_userspace_pid           = FALSE;
	binary_read                  = FALSE;
	user_process_has_been_loaded = FALSE;
	
	return 0;
}

inline void pH_append_call(pH_seq* s, int new_value) {
	if (s->last < 0) { pr_err("%s: s->last is not initialized!\n", DEVICE_NAME); return; }
	ASSERT(s->length != 0);
	
	s->last = (s->last + 1) % (s->length);
	s->data[s->last] = new_value;
}


int pH_add_seq_storage(pH_profile_data *data, int val)
{
    int i;
    
    data->entry[val] = kmalloc(sizeof(pH_seqflags) * PH_NUM_SYSCALLS, GFP_ATOMIC);
    if (!data->entry[val]) {
    	pr_err("%s: Unable to allocate memory in pH_add_seq_storage\n", DEVICE_NAME);
    	return -ENOMEM;
    }
    
    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
    	data->entry[val][i] = 0;
    }
    //pr_err("%s: Iterated over data->entry[val]\n", DEVICE_NAME);
    
    return 0;
}

void pH_add_seq(pH_seq *s, pH_profile_data *data)
{
	int i, cur_call, prev_call, cur_idx;
	u8 *seqdata = s->data;
	int seqlen = s->length;
	//pr_err("%s: Initialized variables for pH_add_seq\n", DEVICE_NAME);

	if (!data || data == NULL) {
		pr_err("%s: ERROR: data is NULL in pH_add_seq\n", DEVICE_NAME);
		return;
	}
	
	ASSERT(seqlen != 0);

	cur_idx = s->last;
	cur_call = seqdata[cur_idx];
	//pr_err("%s: Initialized cur_idx and cur_call\n", DEVICE_NAME);

	for (i = 1; i < seqlen; i++) {
		//pr_err("%s: PH_NUM_SYSCALLS = %d\n", DEVICE_NAME, PH_NUM_SYSCALLS); // PH_NUM_SYSCALLS = 361
		//pr_err("%s: i=%d cur_call=%d prev_call=%d cur_idx=%d\n", DEVICE_NAME, i, cur_call, prev_call, cur_idx);
		if (data->entry[cur_call] == NULL) {
			//pr_err("%s: data->entry[cur_call] == NULL\n", DEVICE_NAME);
			if (pH_add_seq_storage(data, cur_call)) {
				pr_err("%s: pH_add_seq_storage returned a non-zero value\n", DEVICE_NAME);
				return;
			}
		}
		//pr_err("%s: Made it through if\n", DEVICE_NAME);
		prev_call = seqdata[(cur_idx + seqlen - i) % seqlen];
		//pr_err("%s: Set prev_call to %d\n", DEVICE_NAME, prev_call);
		
		//pr_err("%s: The range for cur_call is %p to %p\n", DEVICE_NAME, &(data->entry[cur_call]), &(data->entry[cur_call][PH_NUM_SYSCALLS-1]));
		
		if (cur_call < 0 || cur_call > PH_NUM_SYSCALLS) {
			pr_err("%s: cur_call is out of bounds\n", DEVICE_NAME);
		}
		if (prev_call < 0 || prev_call > PH_NUM_SYSCALLS) {
			pr_err("%s: prev_call is out of bounds\n", DEVICE_NAME);
		}
		if (data->entry[cur_call][prev_call] < 0 || data->entry[cur_call][prev_call] > 256) {
			pr_err("%s: Value is not in the interval [0, 256] (%d)\n", DEVICE_NAME, data->entry[cur_call][prev_call]);
		}
		if (!pH_aremonitoring) {
			return;
		}
		data->entry[cur_call][prev_call] |= (1 << (i - 1));
		//pr_err("%s: data->entry[cur_call][prev_call] = %d\n", DEVICE_NAME, data->entry[cur_call][prev_call]);
	}
}

int pH_test_seq(pH_seq *s, pH_profile_data *data)
{
	int i, cur_call, prev_call, cur_idx;
	u8 *seqdata = s->data;
	int seqlen = s->length;
	int mismatches = 0;

	ASSERT(seqlen != 0);

	cur_idx = s->last;
	cur_call = seqdata[cur_idx];

	// If the current syscall has not been encountered, everything (seqlen-1) is a mismatch
	if (data->entry[cur_call] == NULL)
		    return (seqlen - 1);

	// Iterates over seqlen-1 times - skips 0th position because it was checked above
	for (i = 1; i < seqlen; i++) {
	    // Retrieves the previous call
	    prev_call = seqdata[(cur_idx + seqlen - i) % seqlen];
	    
	    if ((data->entry[cur_call][prev_call] & (1 << (i - 1))) == 0) {
	            mismatches++;
	    }
	}

	return mismatches;
}

inline void pH_train(pH_task_struct *s)
{
    pH_seq *seq = s->seq;
    pH_profile *profile = s->profile;
    pH_profile_data *train = &(profile->train);

	//pr_err("%s: In pH_train\n", DEVICE_NAME);

    train->train_count++;
    if (pH_test_seq(seq, train)) {
        if (profile->frozen) {
                profile->frozen = 0;
                action("%d (%s) normal cancelled", current->pid, profile->filename);
        }
        pH_add_seq(seq, train);
        train->sequences++; 
        train->last_mod_count = 0;

        //pH_log_sequence(profile, seq);
    
    } else {
        unsigned long normal_count; 
        
        train->last_mod_count++;
        
        if (profile->frozen) {
                //mutex_unlock(&(profile->lock));
                return;
        }

        normal_count = train->train_count - train->last_mod_count; 

        if ((normal_count > 0) && ((train->train_count * pH_normal_factor_den) > (normal_count * pH_normal_factor))) {
                action("%d (%s) frozen", current->pid, profile->filename);
                profile->frozen = 1;
                //profile->normal_time = xtime.tv_sec + pH_normal_wait;
        }
    }
}

void pH_profile_data_mem2disk(pH_profile_data *mem, pH_disk_profile_data *disk)
{
    //int i, j;

    disk->sequences = mem->sequences;
    disk->last_mod_count = mem->last_mod_count;
    disk->train_count = mem->train_count;

	/*
    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
            if (mem->entry[i] == NULL) {
                    disk->empty[i] = 1;
                    for (j = 0; j < PH_NUM_SYSCALLS; j++) {
                            disk->entry[i][j] = 0;
                    }
            } else {
                    disk->empty[i] = 0;
                    //memcpy(disk->entry[i], mem->entry[i], PH_NUM_SYSCALLS);
            }
    }
    */
}

// I will eventually want to uncomment the commented lines below and run them without
// any issues
void pH_profile_mem2disk(pH_profile *profile, pH_disk_profile *disk_profile)
{
    /* make sure magic is less than PH_FILE_MAGIC_LEN! */
    strlcpy(disk_profile->magic, PH_FILE_MAGIC, strlen(PH_FILE_MAGIC)+1);
    disk_profile->normal = profile->normal;
	pr_err("%s: original normal is %d\n", DEVICE_NAME, profile->normal);
    disk_profile->frozen = profile->frozen;
    pr_err("%s: original frozen is %d\n", DEVICE_NAME, profile->frozen);
    disk_profile->normal_time = profile->normal_time;
    disk_profile->length = profile->length;
    pr_err("%s: original length is %d\n", DEVICE_NAME, profile->length);
    disk_profile->count = profile->count;
    disk_profile->anomalies = profile->anomalies;
    pr_err("%s: original anomalies is %d\n", DEVICE_NAME, profile->anomalies);
    strncpy(disk_profile->filename, profile->filename, PH_MAX_DISK_FILENAME);

    //pH_profile_data_mem2disk(&(profile->train), &(disk_profile->train));
    //pH_profile_data_mem2disk(&(profile->test), &(disk_profile->test));
}

int pH_profile_data_disk2mem(pH_disk_profile_data *disk, pH_profile_data *mem)
{
    int i;

    mem->sequences = disk->sequences;
    mem->last_mod_count = disk->last_mod_count;
    mem->train_count = disk->train_count;

    for (i = 0; i < PH_NUM_SYSCALLS; i++) {
        if (disk->empty[i]) {
            mem->entry[i] = NULL;
        } else {
            if (pH_add_seq_storage(mem, i))
                return -1;
            memcpy(mem->entry[i], disk->entry[i], PH_NUM_SYSCALLS);
        }
    }
    
    return 0;
}

int pH_profile_disk2mem(pH_disk_profile *disk_profile, pH_profile *profile)
{
    profile->normal = disk_profile->normal;
    profile->frozen = disk_profile->frozen;
    profile->normal_time = disk_profile->normal_time;
    profile->length = disk_profile->length;
    profile->count = disk_profile->count;
    profile->anomalies = disk_profile->anomalies;

    if (pH_profile_data_disk2mem(&(disk_profile->train),
                                 &(profile->train)))
        return -1;

    if (pH_profile_data_disk2mem(&(disk_profile->test),
                                 &(profile->test)))
        return -1;

    return 0;
}

module_init(ebbchar_init);
module_exit(ebbchar_exit);
