#ifndef _FSCHECK_H
#define _FSCHECK_H

#ifdef __cplusplus
extern "C" {
#endif

#define FSCHECK_BLOB_SIZE           (8*1024)
#define FSCHECK_BLOB_SIGNATURE_LEN  (32+1)   // including trailing 0
#define FSCHECK_BLOB_SIGNATURE      "60e7bcaf5cb54657ba9467331ea96bc9"

#define FSCHECK_BLOB_STAGE_INITIALIZED (0xff000000)
#define FSCHECK_BLOB_STAGE_START       (0xff000001)

#define FSCHECK_BLOB_FSTYPE_UNKNOWN (-1)
#define FSCHECK_BLOB_FSTYPE_EXT4    (0)
#define FSCHECK_BLOB_FSTYPE_F2FS    (1)

#define FSCHECK_BLOB_FSTAB_FILE_LEN (128)

typedef struct _FscheckBlob {
    char signature[FSCHECK_BLOB_SIGNATURE_LEN];
    int  size;
    int  fstype;
    int  stage;
    char fstab[FSCHECK_BLOB_FSTAB_FILE_LEN];
    char extra[1];
} FscheckBlob;


FscheckBlob *fscheck_get_blob();
int fscheck_write_blob(FscheckBlob *blob);
int fscheck_set_fstab_path(FscheckBlob *blob, const char *path);
void fscheck_free_blob(FscheckBlob *blob);
void fscheck_print(FscheckBlob *blob);
int fscheck_clear_blob();

#ifdef __cplusplus
}
#endif

#endif // _FSCHECK_H

