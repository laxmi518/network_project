#include <sys/types.h>
#include <sys/sysinfo.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/times.h>
#include <sys/vtimes.h>
 
char * format_bytes_long(long long bytes)
{
	char suffix[][5] = {"B", "KB", "MB", "GB", "TB" };
    int i = 0;
    double dblSByte = (double)bytes;
    if (bytes > 1024)
      for (i = 0; (bytes / 1024) > 0; i++, bytes /= 1024.0)
        dblSByte = bytes / 1024.0;
    char *str = malloc(48);
    sprintf(str,"%f %s",dblSByte,suffix[i]);
    return str;
}

char * format_bytes_int(int bytes)
{
	char suffix[][24] = {"B", "KB", "MB", "GB", "TB","bigger than TB" };
    int i = 0;
    double dblSByte = (double)bytes;
    if (bytes > 1024)
      for (i = 0; (bytes / 1024) > 0; i++, bytes /= 1024.0)
        dblSByte = bytes / 1024.0;
    char *str = malloc(48);
    sprintf(str,"%f %s",dblSByte,suffix[i+1]);
    return str;
}

struct sysinfo memInfo;   
void total_virtual_memory(void)
{
    //struct sysinfo memInfo;
    sysinfo (&memInfo);
    long long totalVirtualMem = memInfo.totalram;
    //Add other values in next statement to avoid int overflow on right hand side...
    totalVirtualMem += memInfo.totalswap;
    totalVirtualMem *= memInfo.mem_unit;
    char *str = format_bytes_long(totalVirtualMem);
    printf("total_virtual_memory = %s \n",str );
    free(str);
}

void total_virtual_memory_currently_used(void)
{
	long long virtualMemUsed = memInfo.totalram - memInfo.freeram;
    //Add other values in next statement to avoid int overflow on right hand side...
    virtualMemUsed += memInfo.totalswap - memInfo.freeswap;
    virtualMemUsed *= memInfo.mem_unit;
    char *str=format_bytes_long(virtualMemUsed);
	printf("total_virtual_memory_currently_used = %s \n",str);
	free(str);
}

int parseLine(char* line){
        int i = strlen(line);
        while (*line < '0' || *line > '9') line++;
        line[i-3] = '\0';
        i = atoi(line);
        return i;
}

void total_memory_currently_used_by_current_process(void)
{
	FILE* file = fopen("/proc/self/status", "r");
    int result = -1;
    char line[128];


    while (fgets(line, 128, file) != NULL){
        if (strncmp(line, "VmSize:", 7) == 0){
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    char *str = format_bytes_int(result);
	printf("total_memory_currently_used_by_current_process = %s\n",str);
	free(str);
}

void total_physical_memory(void)
{
	long long totalPhysMem = memInfo.totalram;
    //Multiply in next statement to avoid int overflow on right hand side...
    totalPhysMem *= memInfo.mem_unit;
    char *str = format_bytes_long(totalPhysMem);
    printf("total_physical_memory = %s\n",str);
    free(str);
}

void total_physical_memory_currently_used(void)
{
	long long physMemUsed = memInfo.totalram - memInfo.freeram;
    //Multiply in next statement to avoid int overflow on right hand side...
    physMemUsed *= memInfo.mem_unit;
    char *str = format_bytes_long(physMemUsed);
	printf("total_physical_memory_currently_used = %s \n",str);
	free(str);
}


void total_phyiscal_memory_currently_used_by_current_process(void)
{
	FILE* file = fopen("/proc/self/status", "r");
	int result = -1;
	char line[128];


	while (fgets(line, 128, file) != NULL){
	    if (strncmp(line, "VmRSS:", 6) == 0){
	        result = parseLine(line);
	        break;
	    }
	}
	fclose(file);
	char *str = format_bytes_int(result);
	printf("total_phyiscal_memory_currently_used_by_current_process = %s\n",str);
	free(str);
}

void cpu_currently_used(void)
{
	static unsigned long long lastTotalUser, lastTotalUserLow, lastTotalSys, lastTotalIdle;

	//init
	FILE* file = fopen("/proc/stat", "r");
	fscanf(file, "cpu %Ld %Ld %Ld %Ld", &lastTotalUser, &lastTotalUserLow,
	    &lastTotalSys, &lastTotalIdle);
	fclose(file);


	double percent;
	FILE* file1;
	unsigned long long totalUser, totalUserLow, totalSys, totalIdle, total;


	file1 = fopen("/proc/stat", "r");
	fscanf(file1, "cpu %Ld %Ld %Ld %Ld", &totalUser, &totalUserLow,
	    &totalSys, &totalIdle);
	fclose(file1);


	if (totalUser < lastTotalUser || totalUserLow < lastTotalUserLow ||
	    totalSys < lastTotalSys || totalIdle < lastTotalIdle){
	    //Overflow detection. Just skip this value.
	    percent = -1.0;
	}
	else{
	    total = (totalUser - lastTotalUser) + (totalUserLow - lastTotalUserLow) +
	        (totalSys - lastTotalSys);
	    percent = total;
	    total += (totalIdle - lastTotalIdle);
	    percent /= total;
	    percent *= 100;
	}


	lastTotalUser = totalUser;
	lastTotalUserLow = totalUserLow;
	lastTotalSys = totalSys;
	lastTotalIdle = totalIdle;

	printf("cpu_currently_used = %f\n",percent);
	//return percent;
}

void cpu_currently_used_by_current_process(void)
{
	static clock_t lastCPU, lastSysCPU, lastUserCPU;
	    static int numProcessors;
	    
	//init
	FILE* file;
	struct tms timeSample;
	char line[128];


	lastCPU = times(&timeSample);
	lastSysCPU = timeSample.tms_stime;
	lastUserCPU = timeSample.tms_utime;


	file = fopen("/proc/cpuinfo", "r");
	numProcessors = 0;
	while(fgets(line, 128, file) != NULL){
	    if (strncmp(line, "processor", 9) == 0) numProcessors++;
	}
	fclose(file);

	//calculate
	struct tms timeSample1;
	clock_t now;
	double percent;


	now = times(&timeSample1);
	if (now <= lastCPU || timeSample1.tms_stime < lastSysCPU ||
	    timeSample1.tms_utime < lastUserCPU){
	    //Overflow detection. Just skip this value.
	    percent = -1.0;
	}
	else{
	    percent = (timeSample1.tms_stime - lastSysCPU) +
	        (timeSample1.tms_utime - lastUserCPU);
	    percent /= (now - lastCPU);
	    percent /= numProcessors;
	    percent *= 100;
	}
	lastCPU = now;
	lastSysCPU = timeSample1.tms_stime;
	lastUserCPU = timeSample1.tms_utime;

	//print percent
	printf("cpu_currently_used_by_current_process = %f\n",percent);
	//return percent;
}

void print_statistics(void)
{
	total_virtual_memory();
	total_virtual_memory_currently_used();
	total_memory_currently_used_by_current_process();
	total_physical_memory();
	total_physical_memory_currently_used();
	total_phyiscal_memory_currently_used_by_current_process();
	cpu_currently_used();
	cpu_currently_used_by_current_process();
}

