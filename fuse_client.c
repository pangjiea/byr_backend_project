#define FUSE_USE_VERSION 31
#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>

ssh_session session;
sftp_session sftp;

int init_sftp_session(const char *host, const char *user, const char *password, int port) {
    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Error creating SSH session\n");
        return -1;
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, host);
    ssh_options_set(session, SSH_OPTIONS_USER, user);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    if (ssh_connect(session) != SSH_OK) {
        fprintf(stderr, "Error connecting to %s: %s\n", host, ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    if (ssh_userauth_password(session, NULL, password) != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Password authentication failed: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    sftp = sftp_new(session);
    if (sftp == NULL) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        return -1;
    }

    if (sftp_init(sftp) != SSH_OK) {
        fprintf(stderr, "Error initializing SFTP session: %s\n", ssh_get_error(session));
        sftp_free(sftp);
        return -1;
    }

    return 0;
}

void write_log_to_server(const char *operation, const char *path) {
    sftp_file log_file;
    char log_path[] = "/tmp/fuse_audit_log.txt";

    time_t now = time(NULL);
    char timestamp[64];

    log_file = sftp_open(sftp, log_path, O_WRONLY | O_CREAT | O_APPEND, S_IRWXU);
    if (!log_file) {
        fprintf(stderr, "Error opening log file on server: %s\n", ssh_get_error(session));
        return;
    }

    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));
    char log_entry[256];
    snprintf(log_entry, sizeof(log_entry), "[%s] Operation: %s, Path: %s\n", timestamp, operation, path);

    if (sftp_write(log_file, log_entry, strlen(log_entry)) < 0) {
        fprintf(stderr, "Error writing to log file: %s\n", ssh_get_error(session));
    }

    sftp_close(log_file);
}

static int client_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    (void) fi;
    sftp_attributes attr;

    printf("Getting attributes for: %s\n", path);
    write_log_to_server("getattr", path);

    attr = sftp_stat(sftp, path);
    if (!attr) {
        fprintf(stderr, "Error getting attributes for %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    memset(stbuf, 0, sizeof(struct stat));
    stbuf->st_mode = attr->permissions;
    stbuf->st_size = attr->size;
    stbuf->st_uid = attr->uid;
    stbuf->st_gid = attr->gid;

    sftp_attributes_free(attr);
    return 0;
}

static int client_readdirplus(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags) {
    (void) offset;
    (void) fi;

    printf("Reading directory with readdirplus: %s\n", path);
    sftp_dir dir = sftp_opendir(sftp, path);
    if (!dir) {
        fprintf(stderr, "Error opening directory %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    sftp_attributes attr;
    while ((attr = sftp_readdir(sftp, dir)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));

        st.st_mode = attr->permissions;
        st.st_size = attr->size;
        st.st_uid = attr->uid;
        st.st_gid = attr->gid;
        st.st_mtime = attr->mtime;
        st.st_atime = attr->atime;

        if (filler(buf, attr->name, &st, 0, FUSE_FILL_DIR_PLUS))
            break;

        sftp_attributes_free(attr);
    }

    sftp_closedir(dir);
    return 0;
}

static int client_open(const char *path, struct fuse_file_info *fi) {
    printf("Opening file: %s\n", path);
    write_log_to_server("open", path);

    sftp_file file = sftp_open(sftp, path, O_RDONLY, 0);
    if (!file) {
        fprintf(stderr, "Error opening file %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }
    fi->fh = (uint64_t)file;
    return 0;
}

static int client_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    sftp_file file = (sftp_file)fi->fh;
    if (!file) {
        return -EBADF;
    }

    printf("Reading file: %s\n", path);
    write_log_to_server("read", path);

    int n = sftp_seek(file, offset);
    if (n != SSH_OK) {
        fprintf(stderr, "Error seeking in file %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    n = sftp_read(file, buf, size);
    if (n < 0) {
        fprintf(stderr, "Error reading file %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    return n;
}

static int client_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    sftp_file file = (sftp_file)fi->fh;

    if (!file) {
        fprintf(stderr, "Error: file %s is not opened\n", path);
        return -EBADF;
    }

    printf("Writing to file: %s\n", path);

    int n = sftp_seek(file, offset);
    if (n != SSH_OK) {
        fprintf(stderr, "Error seeking in file %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    n = sftp_write(file, buf, size);
    if (n < 0) {
        fprintf(stderr, "Error writing to file %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    return n;
}

static int client_release(const char *path, struct fuse_file_info *fi) {
    printf("Releasing file: %s\n", path);
    write_log_to_server("release", path);

    sftp_file file = (sftp_file)fi->fh;
    if (file) {
        sftp_close(file);
    }
    return 0;
}

static int client_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    printf("Creating file: %s\n", path);
    write_log_to_server("create", path);

    sftp_file file = sftp_open(sftp, path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (!file) {
        fprintf(stderr, "Error creating file %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    fi->fh = (uint64_t)file;
    return 0;
}

static int client_mknod(const char *path, mode_t mode, dev_t rdev) {
    printf("Creating node: %s\n", path);
    write_log_to_server("mknod", path);

    sftp_file file = sftp_open(sftp, path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (!file) {
        fprintf(stderr, "Error creating node %s: %s\n", path, ssh_get_error(session));
        return -errno;
    }

    sftp_close(file);
    return 0;
}

static struct fuse_operations client_oper = {
    .getattr = client_getattr,
    .readdir = client_readdirplus,
    .open    = client_open,
    .read    = client_read,
    .write   = client_write,
    .create  = client_create,
    .mknod   = client_mknod,
    .release = client_release,
};

int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <username> <host> <mountpoint>\n", argv[0]);
        return -1;
    }

    const char *user = argv[1];
    const char *host = argv[2];
    const char *mountpoint = argv[3];
    int port = 22;

    char *password = getpass("Enter password: ");

    if (init_sftp_session(host, user, password, port) != 0) {
        return -1;
    }

    printf("Mounting the filesystem at: %s\n", mountpoint);
    int fuse_argc = 5;
    char *fuse_argv[] = { argv[0], (char *) mountpoint, "-o", "writeback_cache,async_read", "-d" };

    return fuse_main(fuse_argc, fuse_argv, &client_oper, NULL);
}
