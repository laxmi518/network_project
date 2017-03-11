/*! \file fetcher_c/fetcher_main.c
* This file is for fetcher
* @author Pritesh acharya 
* @date 9/30/2013     
*/
#include "scp_fetcher.h"



zlog_category_t *c;

void dbg_garray(GArray *filenames)
{
     int j;
	for(j=0;j<filenames->len;j++)
	{
		file_detail_t *file =g_array_index(filenames,file_detail_t *,j);
		printf("filename = %s mktime = %ld\n",file->filename,file->mtime);
	}
}

void libssh2_shutdown(LIBSSH2_SESSION *session)
{
 
    libssh2_session_disconnect(session, "Normal Shutdown, Thank you for playing");

    libssh2_session_free(session);

    // libssh2_exit();
}

LIBSSH2_SESSION * create_session(void)
{

    
    LIBSSH2_SESSION *session;
    session = libssh2_session_init();

    if(!session)
    {
        zlog_error(c, "couldn't create session");
        return NULL;
    }
    return session;
}

LIBSSH2_SFTP * create_sftp_session(LIBSSH2_SESSION *session, config_data_t *config_data,const  char *user,const char *password)
{
    zlog_debug(c,"setup_libssh2");
    int rc,sock, auth_pw=1;
    struct sockaddr_in sin;
    unsigned long hostaddr;
    
    LIBSSH2_SFTP *sftp_session;
    
    hostaddr = inet_addr(config_data->device_ip);
    sock = socket(AF_INET, SOCK_STREAM, 0);
 
    sin.sin_family = AF_INET;
    sin.sin_port = htons(22);
    sin.sin_addr.s_addr = hostaddr;
    if (connect(sock, (struct sockaddr*)(&sin),
            sizeof(struct sockaddr_in)) != 0) {
        zlog_error(c, "failed to connect!");
        return NULL;
    }
    
    /* ... start it up. This will trade welcome banners, exchange keys,
     * and setup crypto, compression, and MAC layers
     */ 
    rc = libssh2_session_handshake(session, sock);

    if(rc) {
        zlog_error(c,"Failure establishing SSH session: %d", rc);
        return NULL;
    }

    // const char *fingerprint = libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    // fprintf(stderr, "Fingerprint: ");
    // int i;
    // for(i = 0; i < 20; i++) {
    //     fprintf(stderr, "%02X ", (unsigned char)fingerprint[i]);
    // }
    // fprintf(stderr, "\n");

    if (auth_pw) {
        /* We could authenticate via password */ 
        if (libssh2_userauth_password(session, user, password)) {

            zlog_error(c, "Authentication by password failed.");
            libssh2_shutdown(session);
            return NULL;
        }
    } else {
        /* Or by public key */ 
        if (libssh2_userauth_publickey_fromfile(session, user,

                            "/home/username/.ssh/id_rsa.pub",
                            "/home/username/.ssh/id_rsa",
                            password)) {
            zlog_error(c,"Authentication by public key failed");
            libssh2_shutdown(session);
            return NULL;
        }
    }
    sftp_session = libssh2_sftp_init(session);
    if (!sftp_session) {
        zlog_error(c,"Unable to init SFTP session");
        libssh2_shutdown(session);
        return NULL;
    }

    /* Since we have not set non-blocking, tell libssh2 we are blocking */ 
    libssh2_session_set_blocking(session, 1);
    return sftp_session;
}



int populate_file_list(LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp_session, GArray *filenames,char *path)
    /* Request a dir listing via SFTP */ 
{

    int rc;
    LIBSSH2_SFTP_HANDLE *sftp_handle;
    sftp_handle = libssh2_sftp_opendir(sftp_session, path);

 
    if (!sftp_handle) {
        zlog_error(c,"Unable to open dir with SFTP");
        libssh2_shutdown(session);
        return -1;
    }
    do {
        char mem[512];
        char longentry[512];
        LIBSSH2_SFTP_ATTRIBUTES attrs;
 
        /* loop until we fail */ 
        rc = libssh2_sftp_readdir_ex(sftp_handle, mem, sizeof(mem),

                                     longentry, sizeof(longentry), &attrs);
        if(rc > 0)
        {
            /* rc is the length of the file name in the mem
               buffer */ 
            if(longentry[0]=='-')
            {
                file_detail_t *file = (file_detail_t*)malloc(sizeof(file_detail_t));
                char *new_path;
                asprintf(&new_path,"%s%s",path,mem);
                file->filename = new_path;
                file->mtime = attrs.mtime;
                // char *mem_dup = strdup(mem);
                // printf("adding mem: %s to array\n",mem_dup);
                // printf("mtime = %ld\n",attrs.mtime);
                filenames = g_array_append_val(filenames,file);
            }
            else if(longentry[0]=='d')// && ( strncmp(mem,"..|| ))
            {
            	int len = strlen(mem);
            	if(
            		(len==1 && (strcmp(mem,".")==0))|| (len==2 &&(strcmp(mem,"..")==0))
            	   )
				{
				}
				else{
					int tot_len = len+strlen(path);
					char new_path[tot_len+2];
					sprintf(new_path,"%s%s/",path,mem);
					new_path[tot_len+1]='\0';
            		populate_file_list(session,sftp_session, filenames,new_path);
				}
            }
        }
        else
        {
        	libssh2_sftp_closedir(sftp_handle);
            break;
        }
 
 	memset(longentry,0,512);
    } while (1);
    // libssh2_sftp_closedir(sftp_handle);
 

    // libssh2_sftp_shutdown(sftp_session);

    return 1;
}

//checks if remote path is file or directory, if file return 1, if directory return 0, on error return -1
int check_remote_path(LIBSSH2_SESSION *session, LIBSSH2_SFTP *sftp_session, GArray *filenames,config_data_t *config_data)
    /* Request a dir listing via SFTP */ 
{
	const char *path = config_data->path;
	int rc;
	int pathlen = strlen(path);
	LIBSSH2_SFTP_HANDLE *sftp_handle = libssh2_sftp_open(sftp_session, path, LIBSSH2_FXF_READ, 0);
    if (!sftp_handle)
     {
        zlog_error(c, "Unable to open file with SFTP: %ld\n",
            libssh2_sftp_last_error(sftp_session));
        libssh2_shutdown(session);
        return -1;
    }
    LIBSSH2_SFTP_ATTRIBUTES attrs;
    rc = libssh2_sftp_fstat(sftp_handle, &attrs);
    if(rc!=0)
    {
    	return -1;
    }
    if(!LIBSSH2_SFTP_S_ISDIR(attrs.permissions))
    {
		zlog_debug(c,"Path is not directory. Path: %s",path);
		file_detail_t *file = (file_detail_t*)malloc(sizeof(file_detail_t));
		file->filename = strdup(path);
		file->mtime = attrs.mtime;
		g_array_append_val(filenames,file);
		libssh2_sftp_close(sftp_handle);
		return 1;

	}

	libssh2_sftp_close(sftp_handle);
	//case directory
	zlog_debug(c,"Path is directory. Path: %s",path);
	int path_len = strlen(path);
	if(path[path_len-1]!='/')
	{
		const char *new_path;
		asprintf(&new_path,"%s/",path);
		AFREE((char *)config_data->path);
		config_data->path = new_path; 		
	}
	return 0;
}

char *calculate_sha1_from_str(char *str)
{
	int i;
	unsigned char obuf[20];
	SHA1(str, strlen(str), obuf);
	char *out = (char *)malloc(sizeof(char)*41); 
	for(i=0; i <20; i++) 
		snprintf(out+i*2, 3, "%02x ", obuf[i]);
	out[40]='\0';
	return out; 
}

char *calculate_sha1_from_file(FILE *fp)
{
	char buf[1024];
	int byte= fread(buf, 1,sizeof(buf), fp);
	if(byte<=0)
	{
		zlog_error(c,"read fail");
	}
	buf[byte]='\0';
	int i;
	unsigned char obuf[20];
	SHA1(buf, strlen(buf), obuf);
	char *out = (char *)malloc(sizeof(char)*61); 
	for(i=0; i <20; i++) 
		snprintf(out+i*2, 3, "%02x ", obuf[i]);
	out[40]='\0';
	rewind(fp);
	return out; 
}

// 
void update_store(const char *sid,const char *file, long mtime, char *sha1, long offset)
{
    // size_t offset = libssh2_sftp_tell(sftp_handle);
	// size_t offset =1;
    zlog_debug(c,"update_store");
    const char * basedir = fet_get_basedir();
    char *checksom_full_path;
    asprintf(&checksom_full_path,"%s%s",basedir,"checksums.json");
    zlog_debug(c, "checksom_full_path = %s",checksom_full_path);
    json_t *checksum_j;
    json_error_t error;
    checksum_j = json_load_file(checksom_full_path, 0, &error);
    if(!checksum_j) {
        /* the error variable contains error information */
        zlog_debug(c,"Error reading config: on line %d: %s\n", error.line, error.text);
        if(error.line!=1)
        {
            goto FREE_AND_RETURN;
        }
        else
        {
            checksum_j = json_object();
        }
    }
#ifdef DEBUG
    printf("Current content of json file\n");
    dbg_j(checksum_j);
#endif
    json_t *sid_j = json_object_get(checksum_j,sid);
    if(sid_j==NULL)
    {   
        zlog_debug(c,"sid doesn't exists");
        sid_j = json_object();
        json_t *file_j = json_object();
        json_t *offset_j = json_object();
        json_object_set_new(offset_j,"offset",json_integer(offset));
        json_object_set_new(offset_j,"mtime",json_integer(mtime));
        json_object_set_new(offset_j,"sha1",json_string(sha1));
        json_object_set_new(file_j,file,offset_j);
        json_object_set_new(sid_j,sid,file_j);
        json_object_update(checksum_j,sid_j);
        json_decref(sid_j);
    }
    else
    {
        zlog_debug(c,"sid exists");
        json_t *file_j = json_object_get(sid_j,file);
        if(file_j==NULL)
        {
            zlog_debug(c,"file doesn't exists");
            file_j = json_object();
            json_t *offset_j = json_object();
            json_object_set_new(offset_j,"offset",json_integer((int)offset));
            json_object_set_new(offset_j,"mtime",json_integer(mtime));
            json_object_set_new(offset_j,"sha1",json_string(sha1));
            json_object_set_new(file_j,file,offset_j);
            json_object_update(sid_j,file_j);
            json_decref(file_j);
        }
        else
        {
            zlog_debug(c,"file exists");
            json_t *offset_j = json_object();
            json_object_set_new(offset_j,"offset",json_integer((int)offset));
            json_object_set_new(offset_j,"mtime",json_integer(mtime));
            json_object_set_new(offset_j,"sha1",json_string(sha1));
            json_object_update(file_j,offset_j);
            json_decref(offset_j);
            // json_object_update(sid_j,file_j);
        }

    }
    json_dump_file(checksum_j, checksom_full_path, JSON_COMPACT);
#ifdef DEBUG
    json_t *json_dump;
    json_error_t error1;
    json_dump = json_load_file(checksom_full_path, 0, &error1);
    if(json_dump==NULL) {
        /* the error variable contains error information */
        zlog_debug(c,"Error reading config: on line %d: %s\n", error1.line, error1.text);
    }
    else
    {
	    printf("updated json file\n");
	    dbg_j(json_dump);
	    json_decref(json_dump);
	}
 #endif

FREE_AND_RETURN:
    json_decref(checksum_j);
    AFREE(checksom_full_path);
    return; 
}

file_store_detail_t *get_file_store_detail_t_from_store(const char *sid, char *file)
{
    zlog_debug(c,"get_offset_and_mtime_from_store");
    const char * basedir = fet_get_basedir();
    char *checksom_full_path;
    asprintf(&checksom_full_path,"%s%s",basedir,"checksums.json");
    zlog_debug(c, "checksom_full_path = %s",checksom_full_path);
    json_t *checksum_j;
    json_error_t error;
    checksum_j = json_load_file(checksom_full_path, 0, &error);
    if(!checksum_j) {
        /* the error variable contains error information */
        zlog_debug(c,"Error reading config: on line %d: %s\n", error.line, error.text);
        goto FREE_MEMORY_AND_RETURN;
    }
#ifdef DEBUG
    printf("Content of json file\n");
    dbg_j(checksum_j);
#endif
    json_t *sid_j=json_object_get(checksum_j,sid);
    if(sid_j==NULL){
        goto FREE_MEMORY_AND_RETURN;
    }
    json_t *file_j=json_object_get(sid_j,file);
    if(file_j==NULL){
        goto FREE_MEMORY_AND_RETURN;
    }
    file_store_detail_t *file_store_detail = (file_store_detail_t *)malloc(sizeof(file_store_detail_t));
    memset(file_store_detail,0,sizeof(file_store_detail_t));
    file_store_detail->offset = get_integer_value_from_json(file_j,"offset");
    file_store_detail->mtime = get_integer_value_from_json(file_j,"mtime");
    const char *sha1 = get_string_value_from_json(file_j,"sha1");
    if(sha1!=NULL)
	    file_store_detail->sha1 = sha1;
    // goto FREE_MEMORY; //can't use goto here
    json_decref(checksum_j);
    AFREE(checksom_full_path);
    return file_store_detail;
FREE_MEMORY_AND_RETURN:
    json_decref(checksum_j);
    AFREE(checksom_full_path);
    return NULL;
}

static int do_mkdir(const char *path, mode_t mode)
{
    // Stat            st;
    struct stat st;
    int             status = 0;

    if (stat(path, &st) != 0)
    {
        /* Directory does not exist. EEXIST for race condition */
        if (mkdir(path, mode) != 0 && errno != EEXIST)
            status = -1;
    }
    else if (!S_ISDIR(st.st_mode))
    {
        errno = ENOTDIR;
        status = -1;
    }

    return(status);
}

/**
** mkpath - ensure all directories in path exist
** Algorithm takes the pessimistic view and works top-down to ensure
** each directory in path exists, rather than optimistically creating
** the last element and working backwards.
*/
int mkpath(const char *path, mode_t mode)
{
    char           *pp;
    char           *sp;
    int             status;
    char           *copypath = strdup(path);

    status = 0;
    pp = copypath;
    while (status == 0 && (sp = strchr(pp, '/')) != 0)
    {
        if (sp != pp)
        {
            /* Neither root nor double slash in path */
            *sp = '\0';
            status = do_mkdir(copypath, mode);
            *sp = '/';
        }
        pp = sp + 1;
    }
    if (status == 0)
        status = do_mkdir(path, mode);
    AFREE(copypath);
    return (status);
}

void check_directory(char *dir_path)
{
	int rc;
	struct stat sb;
	rc = stat(dir_path, &sb);
	if (rc != 0)
	{
		zlog_debug(c,"directory doesn't exists, creating");
		rc = mkpath(dir_path,0755);
	}
	return;
}

char *get_str_before_char(const char *str,char a)
{
    const char *ptr = strchr(str, a);
    if(ptr) 
    {
       int index = ptr - str;
       char *new_str = malloc(sizeof(char)*index+1);
       strncpy(new_str,str,index);
       new_str[index]='\0';
       return new_str;
    }
    else
    {
        return NULL;
    }
}

int get_filetype(magic_t magic_cookie,char *full_path)
{
	int type=FILETYPE_UNKNOWN;
	zlog_debug(c,"get_filetype. full_path: %s",full_path);
    const char *magic_full = magic_file(magic_cookie,(const char *)full_path);
    if(magic_full==NULL)
    {
    	zlog_error(c,"error on magic_file");
    	return type;
    }
    char *file_type = get_str_before_char(magic_full, ';');
    
	if(strncmp(file_type,"text/",5)==0)
		type=FILETYPE_PLAINTEXT;
	else if(strcmp(file_type,"application/x-bzip2")==0)
		type=FILETYPE_TAR;
	else if(strcmp(file_type,"application/x-tar")==0)
		type=FILETYPE_TAR;
	else if(strcmp(file_type,"application/x-gzip")==0)
		type=FILETYPE_TAR;
	else if(strcmp(file_type,"application/zip")==0)
		type=FILETYPE_ZIP;
    else if(strcmp(file_type,"application/xml")==0)
        type=FILETYPE_PLAINTEXT;
	AFREE(file_type);
    return type;

}

void process_single_extracted_file(config_data_t *config_data, char *full_path)
{
	FILE *fp = fopen(full_path, "rt");
	if(fp==NULL)
	{
		zlog_error(c,"Couldn't open file");
		return;	
	}
	char *line = NULL;
	size_t len = 0;
	ssize_t read;
    while(1){
        read = getline(&line, &len, fp);
        // printf("\n%s\n", line);
        if(read == -1)
        {
            AFREE(line);
            break;
        }
        if(line[read-1]=='\n')
            line[read-1]='\0';
        if(line[0] == ' ' || line[0] == '\0')
        {
            line = fet_trim_whitespace(line);
            if(strcmp(line,"")==0)
            {
                AFREE(line);
                line = NULL;
                continue;
            }
        }
        json_t *event = fet_create_basic_event(line,config_data);
        // json_t *event = fet_create_event(line,sid_param);
        fet_send_event(event, config_data);
        AFREE(line);
        line =NULL;
    }
	fclose(fp);  /* close the file prior to exiting the routine */
}


void process_extracted_files(config_data_t *config_data,magic_t magic_cookie,file_detail_t *file, char *full_path)
{
	zlog_debug(c,"process_extracted_files, dir_name = %s\n",full_path);
	DIR * d;

    /* Open the directory specified by "dir_name". */
    d = opendir (full_path);

    /* Check it was opened. */
    if (! d) {
        fprintf (stderr, "Cannot open directory '%s': %s\n",
                 full_path, strerror (errno));
        exit (EXIT_FAILURE);
    }
    while (1) {
        struct dirent * entry;
        const char * d_name;

        /* "Readdir" gets subsequent entries from "d". */
        entry = readdir (d);
        if (! entry) {
            /* There are no more entries in this directory, so break
               out of the while loop. */
            break;
        }
        d_name = entry->d_name;
        /* Print the name of the file and directory. */


        /* See if "entry" is a subdirectory of "d". */

        if (entry->d_type & DT_DIR) {

            /* Check that the directory is not "d" or d's parent. */
            
            if (strcmp (d_name, "..") != 0 &&
                strcmp (d_name, ".") != 0) {
                int path_length;
                char path[PATH_MAX];
 
                path_length = snprintf (path, PATH_MAX,
                                        "%s%s/", full_path, d_name);
                path[path_length]='\0';
                // printf ("%s\n", path);
                if (path_length >= PATH_MAX) {
                    fprintf (stderr, "Path length has got too long.\n");
                    exit (EXIT_FAILURE);
                }
                /* Recursively call "list_dir" with the new path. */
                // char *new_relative_path;
                // asprintf(&new_relative_path,"%s%s/",relative_path,d_name);
                // printf("new_relative_path = %s\n",new_relative_path);
                process_extracted_files(config_data,magic_cookie,file,path);
                // AFREE(new_relative_path);
            }
        }
        else
        {
            char *full_path_file;
            asprintf(&full_path_file,"%s%s",full_path,d_name);
			int type = get_filetype(magic_cookie,full_path_file);
            if(type==FILETYPE_PLAINTEXT)
            {
            	process_single_extracted_file(config_data,full_path_file);
            }
            free(full_path_file);
        }
    }
    /* After going through all the entries, close the directory. */
    if (closedir (d)) {
        fprintf (stderr, "Could not close '%s': %s\n",
                 full_path, strerror (errno));
        exit (EXIT_FAILURE);
    }
}

void process_single_file(config_data_t *config_data,file_detail_t *file,char *full_path)
{
	zlog_debug(c,"processing file:  %s",full_path);
	file_store_detail_t *file_store_detail= get_file_store_detail_t_from_store(config_data->sid, file->filename);
	long int offset=0;

	FILE *fp = fopen(full_path, "rt");
	if(fp==NULL)
	{
		zlog_error(c,"Couldn't open file");
		AFREE(file_store_detail);
		return;	
	}
	char *sha1_hash = calculate_sha1_from_file(fp);
	zlog_debug(c,"sha1_hash = %s",sha1_hash);

	if(file_store_detail != NULL)
	{
		offset = file_store_detail->offset;
		if(strcmp(sha1_hash,file_store_detail->sha1)!=0)
		{
			zlog_debug(c,"hash has changed, reading from zero again");
	    	offset = 0;
		}
	}
	if(offset>0)
	{
		fseek(fp,offset,0);
	}
	zlog_debug(c,"Reading from Offset: %ld",offset);

	char *line = NULL;
	size_t len = 0;
	ssize_t read = 0;
	while(1){
        read = getline(&line, &len, fp);
		// printf("\n%s\n", line);
        if(read == -1)
        {
            AFREE(line);
            break;
        }
		if(line[read-1]=='\n')
			line[read-1]='\0';
        if(line[0]==' ' || line[0] == '\0')
        {
            line = fet_trim_whitespace(line);
            if(strcmp(line,"")==0)
            {
                AFREE(line);
                line = NULL;
                continue;
            }
        }
		json_t *event = fet_create_basic_event(line,config_data);
		// json_t *event = fet_create_event(line,sid_param);
		fet_send_event(event, config_data);
		AFREE(line);
		line =NULL;
	}

	long new_offset = ftell(fp);
	fclose(fp);  /* close the file prior to exiting the routine */
	update_store(config_data->sid, file->filename,file->mtime, sha1_hash,new_offset);
    AFREE(sha1_hash);
	AFREE(file_store_detail);	
}

void process_files(config_data_t *config_data, magic_t magic_cookie,file_detail_t *file, char *full_path)
{
	zlog_debug(c,"process_for_compressed_files. full_path = %s\n",full_path);
	int type = get_filetype(magic_cookie,full_path);
	if(type == FILETYPE_PLAINTEXT)
	{
		process_single_file(config_data,file,full_path);
	}
	else if(type != FILETYPE_UNKNOWN)
	{				
		char *untar_command=NULL;
		if(type==FILETYPE_TAR)
			asprintf(&untar_command,"%s%s",CMD_TAR,full_path);
		else if(type==FILETYPE_GZIP)
			asprintf(&untar_command,"%s%s",CMD_GZ,full_path);
		else if(type==FILETYPE_ZIP)
			asprintf(&untar_command,"%s%s",CMD_ZIP,full_path);
		if(untar_command!=NULL)
		{
			// check_directory(dir_path);
			char *full_path_dup = strdup(full_path);
			char *dir_path = dirname(full_path_dup);
			char *full_path_dup2 = strdup(full_path);
			char *filename_with_extension = basename(full_path_dup2);
			// char *filename = get_str_before_char(filename_with_extension,'.');
			char *filename_sha1 = calculate_sha1_from_str(filename_with_extension);
			char *command;
			asprintf(&command,"cd %s; mkdir %s ; cd %s ; %s",dir_path,filename_sha1,filename_sha1,untar_command);
			int rc = system(command);
			if(rc==0){
				char *path_of_extract;
				asprintf(&path_of_extract,"%s/%s/",dir_path,filename_sha1);
				process_extracted_files(config_data,magic_cookie,file,path_of_extract);
				AFREE(path_of_extract);
				update_store(config_data->sid, file->filename,file->mtime, "",0);
			}
			AFREE(full_path_dup2);
			AFREE(filename_sha1);
			AFREE(full_path_dup);
			AFREE(command);
			AFREE(untar_command);
		}
	}	
	else
	{
		zlog_error(c,"Unknown filetype");	
	}
}

int copy_and_process_files(LIBSSH2_SESSION *session,config_data_t *config_data, GArray *filenames,char *basedir, magic_t magic_cookie)
{
	int i;
	for(i=0;i<filenames->len;i++)
	{
	    file_detail_t *file =g_array_index(filenames,file_detail_t *,i);
		zlog_debug(c,"filename = %s\n",file->filename);
		// zlog_debug(c,"mktime = %ld\n",file->mtime);
		struct stat    fileinfo;
		/* Request a file via SCP */ 
	    LIBSSH2_CHANNEL *channel = libssh2_scp_recv(session, file->filename, &fileinfo);

	 
	    if (!channel) {

	        zlog_error(c, "Unable to open a session: %d\n",
	                libssh2_session_last_errno(session));
	        // libssh2_shutdown(session);
	        return -1;
	    }
	 
		off_t got=0;
		char *full_path;
		asprintf(&full_path, "%s%s",basedir,file->filename);
		char *full_path_dup = strdup(full_path);
		char *dir_path = dirname(full_path_dup);
		check_directory(dir_path);
		AFREE(full_path_dup);
		FILE *fp;
		errno=0;

		fp=fopen(full_path, "w");
		if(fp!=NULL)
		{
			int fd = fileno(fp);
		    while(got < fileinfo.st_size) {
		        char mem[1024*128];
		        int amount=sizeof(mem);
		 
		        if((fileinfo.st_size -got) < amount) {
		            amount = fileinfo.st_size -got;
		        }
		 
		        ssize_t rc = libssh2_channel_read(channel, mem, amount);

		        if(rc > 0) {
		        	//mem[rc]='\0';
					write(fd, mem,rc);
		            // write(1, mem, rc);
		        }
		        else if(rc < 0) {
		            zlog_error(c,"libssh2_channel_read() failed: %zd", rc);
		            // fclose(fp);
		            break;
		        }
		        memset(mem,0x0,sizeof(mem));
		        got += rc;
		    }
		    fclose(fp);
		}
		else
		{
			// printf("unable to open file %s\n",strerror(errno));
			zlog_error(c,"Unable to open file.");
		}
		process_files(config_data, magic_cookie,file, full_path);

	    libssh2_channel_free(channel);

	    channel = NULL;
	    AFREE(full_path);
	}
}

void filter_filenames_by_regex(GArray *filenames,const char *regex)
{
    int j;
	for(j=0;j<filenames->len;j++)
	{
		file_detail_t *file =g_array_index(filenames,file_detail_t *,j);
		if(g_regex_match_simple(regex,file->filename,0,0)==FALSE)
		{
			AFREE(file->filename);
			AFREE(file);
			g_array_remove_index (filenames,j);	
		}
	}
}

void filter_filenames_by_mtime(GArray *filenames, config_data_t *config_data)
{
    int j;
	for(j=0;j<filenames->len;j++)
	{
		file_detail_t *file =g_array_index(filenames,file_detail_t *,j);
		file_store_detail_t *file_store_detail= get_file_store_detail_t_from_store(config_data->sid, file->filename);
        if(file_store_detail != NULL)
        {
        	if(file_store_detail->mtime == file->mtime)
        	{
        		AFREE(file->filename);
        		AFREE(file);
				filenames = g_array_remove_index (filenames,j);
				j--;        		
        	}
        	AFREE(file_store_detail);	
        }
	}
}

magic_t setup_libmagic()
{
    const char *magic_full;
    ;
    /*MAGIC_MIME tells magic to return a mime of the file, but you can specify different things*/
    magic_t magic_cookie = magic_open(  MAGIC_MIME);
        if (magic_cookie == NULL) {
            zlog_error(c,"unable to initialize magic library\n");
            return NULL;
            }
        if (magic_load(magic_cookie, NULL) != 0) {
            zlog_error(c,"cannot load magic database - %s\n", magic_error(magic_cookie));
            magic_close(magic_cookie);
            return NULL;
        }
        return magic_cookie;
}

int ensure_checksum_file(const char *basedir)
{
	zlog_debug(c,"ensure_checksum_file, basedir: %s",basedir);
	char *checksum_path;
	asprintf(&checksum_path,"%s%s",basedir,"checksums.json");
	if(access(checksum_path, F_OK ) != -1) 
	{
		zlog_debug(c,"file exists, do nothing");		
	} 
	else
	{
	    // file doesn't exist
	    zlog_debug(c, "file doesn't exists, creating");
		FILE *fp = fopen(checksum_path, "ab+");
		if(fp==NULL)
		{
			AFREE(checksum_path);
			return -1;
		}
	}
	AFREE(checksum_path);
    return 1;
}

/**
*Callback function of thread creation, when the thread starts execution, it will come to this callback.
*@ param[in] param which contais sid information
*@return void pointer.
*/ 

void *thread_main_cb(void *param)
{
    //start of thread execution time
    int rc;
    json_t* sid_param = (json_t*)param;
    if(sid_param == NULL)
    {
        zlog_error(c, "parameter is null. couldn't start thread");
        return NULL;
    }
    //log file path
    config_data_t *config_data= fet_get_config_data(param);
    const char *basedir = fet_get_basedir();
    rc = ensure_checksum_file(basedir);
    if(rc == -1)
    {
    	return NULL;
    }
    const char *user = get_string_value_from_json(param, "user");
    const char *password = get_string_value_from_json(param, "password");

	magic_t magic_cookie = setup_libmagic();
	if(magic_cookie==NULL)
	{
		zlog_error(c,"libmagic not initialized, exiting");
		return NULL;
	}

    while(1)
    {
        GArray *filenames = g_array_new(TRUE,TRUE,sizeof(file_detail_t *));
        LIBSSH2_SESSION *session = create_session();
        LIBSSH2_SFTP *sftp_session = create_sftp_session(session, config_data, user, password);
        if(sftp_session==NULL)
        {
            break;
        }
        rc = check_remote_path(session, sftp_session,filenames, config_data);
        if(rc==-1)
        {
	        sleep(config_data->fetch_interval_seconds);
        	continue;
        }
        else if(rc ==0)
        {
        	//remote path is directory
	        rc = populate_file_list(session, sftp_session,filenames, config_data->path);
	        if(rc==-1)
	        {
	        	sleep(config_data->fetch_interval_seconds);
	        	continue;
	        }
	    }
        // const char *basedir = fet_get_basedir();
        char *basedir_full;
        asprintf(&basedir_full,"%s%s/",basedir,config_data->device_ip);

#ifdef DEBUG
        printf("before regex\n");
        dbg_garray(filenames);
#endif
        const char *regex = get_string_value_from_json(param, "regex");
        zlog_debug(c,"regex = %s",regex);
        filter_filenames_by_regex(filenames, regex);
        filter_filenames_by_mtime(filenames,config_data);
#ifdef DEBUG
        printf("after applying regex and filtering by mtime\n");
        dbg_garray(filenames);
#endif  
        rc = copy_and_process_files(session, config_data,filenames,basedir_full,magic_cookie);
        if(rc==-1)
        {
        }

        //remove all created files and directories
        char *rm_command;
        asprintf(&rm_command,"cd %s ; rm -rf %s",basedir,config_data->device_ip);
        rc = system(rm_command);
        AFREE(rm_command);

        //free filenames garray iteratatively
        int j;
    	for(j=0;j<filenames->len;j++)
		{
			file_detail_t *file =g_array_index(filenames,file_detail_t *,j);
			AFREE(file->filename);
            AFREE(file);
			g_array_remove_index (filenames,j);	
            j--;
		}
        g_array_unref(filenames);
        libssh2_sftp_shutdown(sftp_session);
        libssh2_shutdown(session);
		AFREE(basedir_full);
        zlog_debug(c,"------------------------------next-run------------------------------");
        sleep(config_data->fetch_interval_seconds);
    }
}


/**
* Main function, which is setting the value of config_path and calling the interface function.
*/ 

int main(int argc, char **argv)
{
    char *config_path = argv[1];
    fet_init_library(config_path,"scp_c_fetcher", "/opt/immune/storage/col/zlog_scp_fetcher.conf");
    c = fet_get_zlog_category();
    if(argv[1] == NULL) {
        zlog_fatal(c,"A config file is expected as argument.\n");
        exit(1);
    }
    /* Create a session instance*/ 
    int rc = libssh2_init (0);
    if (rc != 0)
    {
        zlog_error(c,"libssh2 initialization failed (%d)",rc);
        return -1;
    }
    fet_register_callbacks(thread_main_cb);
    fet_start();
    return 0;
 }