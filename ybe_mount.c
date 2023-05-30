#include "yb.h"
#include "ybe_common.h"
#include <errno.h>
#define FUSE_USE_VERSION 32
#include <fuse3/fuse.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static FILE *fin;
#ifdef DEB
static FILE *log=NULL;
#endif
static char *bin_path=NULL;
static char *iso_path=NULL;
static uint8_t *enc;
static uint64_t *dloc;
static uint32_t sector_cnt;

static inline _Bool pathmatch(const char *key, const char *existing){
	if(!key || !existing)
		return 0;
	return str_ends_with(key, existing);
}

int ybe_mnt_getattr(const char *path, struct stat *st, struct fuse_file_info *fi){
#ifdef DEB
	if(log){fprintf(log, "getattr '%s'\n", path);fflush(log);}
#endif
	memset(st, 0, sizeof(struct stat));
	st->st_uid = getuid();
	st->st_gid = getgid();
	if(strcmp(path, "/")==0){
		st->st_mode=S_IFDIR | 0755;
		st->st_nlink=2;
	}
	else if(pathmatch(path, bin_path)){
		st->st_mode=S_IFREG | 0644;
		st->st_nlink=1;
		st->st_size=sector_cnt*2352;
	}
	else if(pathmatch(path, iso_path)){
		st->st_mode=S_IFREG | 0644;
		st->st_nlink=1;
		st->st_size=sector_cnt*2048;
	}
	else
		return -ENOENT;
	return 0;
}

int ybe_mnt_open(const char *path, struct fuse_file_info *fi){
#ifdef DEB
	if(log){fprintf(log, "open\n");fflush(log);}
#endif
	if((!pathmatch(path, bin_path))&&(!pathmatch(path, iso_path)))
		return -EBADF;
	return 0;
}

static void generate_sector(uint8_t *sector, size_t index, FILE *fin){
	uint8_t data[2352];
	yb g={0};
	g.sector_address=150+index;
	g.enc=enc+(index*292);
	g.data=data;
	g.sector=sector;
	fseek(fin, dloc[index], SEEK_SET);
	fread(data, 1, yb_type_to_data_len(enc[index*292]), fin);
	decode_sector(&g);
}

static inline size_t smol(size_t a, size_t b){
	return a<b?a:b;
}

static inline size_t memcpy_cnt(void *dest, const void *src, size_t n){
	memcpy(dest, src, n);
	return n;
}

int ybe_mnt_read(const char *path, char *buf, size_t len, off_t offset, struct fuse_file_info *fi){
#ifdef DEB
	if(log){fprintf(log, "read\n");fflush(log);}
#endif
	if(!len)
		return 0;

	if(pathmatch(path, iso_path)){
		if(offset>=(sector_cnt*2048))
			return -EOF;
		len = (offset+len)>(sector_cnt*2048)?(sector_cnt*2048)-offset:len;
		fseek(fin, dloc[0]+offset, SEEK_SET);
		return fread(buf, 1, len, fin);
	}

	if(pathmatch(path, bin_path)){
		size_t index, ret=0;
		uint8_t sector[2352];
		if(offset>=(sector_cnt*2352))
			return -EOF;
		len = (offset+len)>(sector_cnt*2352)?(sector_cnt*2352)-offset:len;
		index=offset/2352;

		if(offset%2352){//first sector starts unaligned
			generate_sector(sector, index, fin);
			ret+=memcpy_cnt(buf+ret, sector+(offset%2352), smol((2352-(offset%2352)), len-ret));
			++index;
		}
		for(;ret!=len;++index){
			generate_sector(sector, index, fin);
			ret+=memcpy_cnt(buf+ret, sector, smol(2352, len-ret));
		}
		return ret;
	}
	return 0;
}

int ybe_mnt_readdir(const char *path, void *buffer, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi, enum fuse_readdir_flags flags){
#ifdef DEB
	if(log){fprintf(log, "readdir\n");fflush(log);}
#endif
	filler(buffer, ".", NULL, 0, 0);
	filler(buffer, "..", NULL, 0, 0);
	if(strcmp(path, "/" )==0){
		if(bin_path)
			filler(buffer, bin_path, NULL, 0, 0);
		if(iso_path)
			filler(buffer, iso_path, NULL, 0, 0);
	}
	return 0;
}

int ybe_mnt_release(const char *path, struct fuse_file_info *fi){
#ifdef DEB
	if(log){fprintf(log, "release\n");fflush(log);}
#endif
	if((!pathmatch(path, bin_path))&&(!pathmatch(path, iso_path)))
		return -EBADF;
	return 0;
}

struct fuse_operations ybe_mnt_ops = {
	.getattr=ybe_mnt_getattr,
	.open=ybe_mnt_open,
	.read=ybe_mnt_read,
	.readdir=ybe_mnt_readdir,
	.release=ybe_mnt_release,
};

int main(int argc, char *argv[]){
	char *fuseops[6]={"ybe_mount", NULL, "-o", "ro", "-s", NULL};
	size_t i;
	uint8_t crunch;
	uint64_t dloc_build;
	if(argc!=3)
		return printf("Usage: ybe_mount mount_dir ybe_file.ybe\n");

#ifdef DEB
	log=fopen("log.txt", "wb");
#endif

	_if(strcmp(argv[2], "-")==0, "cannot mount from stdin");
	_if(!(fin=fopen(argv[2], "rb")), "Input stream cannot be NULL");
	ybe_read_header(fin, &sector_cnt, &crunch);
	enc=ybe_read_encoding(fin, sector_cnt, crunch);
	dloc=malloc(sector_cnt*sizeof(uint64_t));

	bin_path=malloc(strlen(argv[2]+5));
	sprintf(bin_path, "%s.bin", argv[2]);
	if(str_ends_with(argv[2], ".bin.ybe"))
		sprintf(bin_path+strlen(bin_path)-11, "bin");
	dloc_build=ftell(fin);
	for(i=0;i<sector_cnt;++i){
		dloc[i]=dloc_build;
		dloc_build+=yb_type_to_data_len(enc[i*292]);
	}

	for(i=0;i<sector_cnt;++i){//test if iso can be mounted
		if(yb_type_to_data_len(enc[i*292])!=2048)
			break;
	}
	if(i==sector_cnt){
		iso_path=malloc(strlen(argv[2]+5));
		sprintf(iso_path, "%s.iso", argv[2]);
		if(str_ends_with(argv[2], ".bin.ybe"))
			sprintf(iso_path+strlen(iso_path)-11, "iso");
	}

#ifdef DEB
	if(log){fprintf(log, "sector_cnt: %"PRIu32"\n", sector_cnt);fflush(log);}
	if(log){fprintf(log, "iso_loc: %"PRIi64"\n", dloc[0]);fflush(log);}
	if(log){fprintf(log, "bin_path '%s'\n", bin_path);fflush(log);}
	if(log){fprintf(log, "iso_path '%s'\n", iso_path);fflush(log);}
	if(log){fprintf(log, "pass to fuse\n");fflush(log);}
#endif

	eccedc_init();
	fuseops[1]=argv[1];
	fuse_main(5, fuseops, &ybe_mnt_ops, NULL);
	if(bin_path)free(bin_path);
	if(iso_path)free(iso_path);
	if(enc)free(enc);
	if(dloc)free(dloc);
#ifdef DEB
	if(log)fclose(log);
#endif
}
