// My definitions
#define TRUE         (1 == 1)
#define FALSE        (!TRUE)

// Anil's definitions
#ifndef num_syscalls
#define num_syscalls (361)
#endif // num_syscalls

//#define PH_NUM_SYSCALLS 256 // Size of array
#define PH_NUM_SYSCALLS num_syscalls
#define PH_MAX_DISK_FILENAME 256
#define PH_FILE_MAGIC_LEN 20

typedef int pH_seqflags;

typedef struct pH_disk_profile_data {
        int sequences;  /* # sequences that have been inserted */
                        /*   NOT the number of lookahead pairs */
        unsigned long last_mod_count; /* # syscalls since last modification */
        unsigned long train_count;      /* # syscalls seen during training */
        int empty[PH_NUM_SYSCALLS];
        pH_seqflags entry[PH_NUM_SYSCALLS][PH_NUM_SYSCALLS];
} pH_disk_profile_data;

typedef struct pH_disk_profile {
	// Anil's old fields
        char magic[PH_FILE_MAGIC_LEN];  /* file magic: identifier, version */
        int normal;
        int frozen;
        time_t normal_time;
        int length;
        unsigned long count;
        int anomalies;
        pH_disk_profile_data train, test;
        char filename[PH_MAX_DISK_FILENAME];

	// My new fields
	struct pH_disk_profile* next; // For linked list queue implementation
} pH_disk_profile;
