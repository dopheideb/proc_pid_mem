// Copyright (C) 2022 Bart Dopheide <dopheide at fmf dot nl>
// 
// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by 
// the Free Software Foundation, version 2 of the License.
// 
// This program is distributed in the hope that it will be useful, but 
// WITHOUT ANY WARRANTY; without even the implied warranty of 
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
// General Public License for more details.



// We need memmem().
#define _GNU_SOURCE

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>



// Flag set by '--verbose'.
static int verbosity;

void log_format(char const * tag, char const * format, va_list args)
{
	// We fancy subsecond precision. ANSI C has no solution. POSIX 
	// does.
	struct timeval now;
	gettimeofday(&now, NULL);
	
	struct tm * lt = localtime(&now.tv_sec);
	char datetime[128];
	strftime(datetime, sizeof(datetime), "%Y-%m-%d %H:%M:%S", lt);
	
	fprintf(stderr, "%s.%06ld [%s] ", datetime, now.tv_usec, tag);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
}

void log_error(char const * const format, ...)
{
	va_list args;
	va_start(args, format);
	log_format("ERROR", format, args);
	va_end(args);
}

void log_debug(char const * const message, ...)
{
	if (verbosity < 1)
	{
		return;
	}
	va_list args;
	va_start(args, message);
	log_format("DEBUG", message, args);
	va_end(args);
}

void log_debug2(char const * const message, ...)
{
	if (verbosity < 2)
	{
		return;
	}
	va_list args;
	va_start(args, message);
	log_format("DBG#2", message, args);
	va_end(args);
}



enum action
{
	action_dump,
	action_search_all_mem,
	action_search_non_file,
};
int action = action_search_non_file;

// This struct represents the information of a single line in 
// /proc/pid/maps.
//
// The member names mostly come from "man 5 proc".
struct proc_pid_maps_item
{
	unsigned long long start;
	unsigned long long end;
	char permissions[4+1];
	unsigned long long offset;
	char dev[5+1];
	unsigned long long inode;
	char pathname[PATH_MAX];
};



struct option_tt
{
	union
	{
		unsigned long long ull;
		char * cptr;
	};
};



// Parses /proc/pid/maps file.
//
// Return value: a list of type "struct proc_pid_maps_item". The list 
// ends where all members are zero. For string members, this means the 
// first char is 0.
struct proc_pid_maps_item * parse_maps(pid_t pid)
{
	// Build the return value as we go, with realloc().
	struct proc_pid_maps_item * retval = NULL;
	
	// "/proc/"   pid   "/maps" '\0'
	// 5          + 20  + 5     + 1 = 31
	// 
	// (2 ** 64) - 1 == 18446744073709551616, 20 characters
	//
	// 31? Let's make it 32.
	char proc_pid_maps_filename[32];
	sprintf(proc_pid_maps_filename, "/proc/%d/maps", pid);
	
	// Open maps file read-only.
	FILE * proc_pid_maps = fopen(proc_pid_maps_filename, "r");
	if (proc_pid_maps == NULL)
	{
		log_error("Failed to open maps file '%s'.", proc_pid_maps_filename);
		return NULL;
	}
 	
	// The column "pathname" may be PATH_MAX long on Linux. All the 
	// other column are short and do not vary or don't vary much, so 
	// let's just allocate PATH_MAX for those columns too.
	unsigned const max_line_size = PATH_MAX + PATH_MAX;
	char line[max_line_size];
	unsigned item_idx = 0;
	
	// Read and parse maps file line by line.
	while (fgets(line, max_line_size, proc_pid_maps))
	{
		// Remove "\n" (easier for printing).
		line[strcspn(line, "\n")] = 0;
		log_debug2("line='%s'", line);
		
		// Enlarge our lists with a single item.
		// 
		// The "+ 2" could have been "+ 1", but we know at 
		// forehand that must write a terminating all zero item 
		// as well. The "+ 2" saves us from duplicating code.
		retval = realloc(
			retval,
			(item_idx + 2) * sizeof(struct proc_pid_maps_item)
		);
		if (retval == NULL)
		{
			log_error("realloc() failed.");
			return NULL;
		}
		
		// Example of what to parse:
		// address                   perms offset  dev   inode                      pathname
		// 55ffa58e7000-55ffa5917000 r--p 00000000 fd:01 8666                       /usr/bin/bash
		// ^            ^            ^
		// start offset |            |
		//              |end+1       flags
		// Spaces, not tabs.
		int num_parsed = sscanf(line, "%Lx-%Lx %4s %Lx %5s %Lu %s",
			&retval[item_idx].start,	// 1
			&retval[item_idx].end,		// 2
			 retval[item_idx].permissions,	// 3
			&retval[item_idx].offset,	// 4
			 retval[item_idx].dev,		// 5
			&retval[item_idx].inode,	// 6
			 retval[item_idx].pathname	// 7. Note: optional!
		);
		if (num_parsed < 6)
		{
			log_error("Could not parse this line: '%s'", line);
			continue;
		}
		
		log_debug2("start='%#Lx'", retval[item_idx].start);
		log_debug2("end='%#Lx'", retval[item_idx].end);
		log_debug2("permissions='%s'", retval[item_idx].permissions);
		log_debug2("offset='%#Lx'", retval[item_idx].offset);
		log_debug2("dev='%s'", retval[item_idx].dev);
		log_debug2("inode='%Lu'", retval[item_idx].inode);
		log_debug2("pathname='%s'", retval[item_idx].pathname);
		 
		++item_idx;
	}
	
	// Mark the end of the list.
	retval[item_idx].start		= 
	retval[item_idx].end		= 
	retval[item_idx].permissions[0]	= 
	retval[item_idx].offset		= 
	retval[item_idx].dev[0]		= 
	retval[item_idx].inode		= 
	retval[item_idx].pathname[0]	= 0;
	
	return retval;
}



void read_proc_pid_mem(pid_t pid, struct option_tt * options)
{
	char * needle = options['s'].cptr;
	unsigned needle_len = 0;
	if (needle != NULL)
	{
		needle_len = strlen(needle);
	}
	
	struct proc_pid_maps_item * proc_pid_maps_items = parse_maps(pid);
	
	char mem_file_name[1024];
	log_debug("PID: %d", pid);
	sprintf(mem_file_name, "/proc/%d/mem", pid);
	
	int mem_fd = open(mem_file_name, O_RDONLY);
	if (mem_fd < 0)
	{
		log_error("Error opening proc mem file '%s'.", mem_file_name);
		return;
	}
	
	// We need ptrace, otherwise we cannot read the program memory.
	ptrace (PTRACE_ATTACH, pid, NULL, NULL);
	waitpid (pid, NULL, 0);
	
	char * mem_buf = NULL;
	unsigned long long mem_buf_size = 0;
	struct proc_pid_maps_item * proc_pid_maps_item = proc_pid_maps_items;
	while (proc_pid_maps_item->permissions[0] != 0)
	{
		// NOTE: /proc/pid/mem does NOT support mmap(), only:
		// lseek
		// read
		// write
		// open
		// release
		log_debug2("start=%#Lx", proc_pid_maps_item->start);
		
		unsigned long long size =
			proc_pid_maps_item->end
			-
			proc_pid_maps_item->start;
		lseek(mem_fd, proc_pid_maps_item->start, SEEK_SET);
		
		// (Re)allocate enough buffer space.
		if (size > mem_buf_size)
		{
			mem_buf_size = size;
			mem_buf = (char *) realloc(mem_buf, mem_buf_size);
			 
			if (mem_buf == NULL)
			{
				log_error("realloc() failed.");
				return;
			}
		}
		
		// Read whole memory region into our memory. Silly, but 
		// mmap() doesn't work in/on /proc/pid/mem.
		read(mem_fd, mem_buf, size);
		
		if (options['d'].ull)
		{
			if (!options['h'].ull)
			{
				write(1, mem_buf, size);
			}
			else
			{
				if (options['f'].ull && proc_pid_maps_item->pathname[0] == '/')
				{
					log_debug2("Skipping memory region, since it is mmap()'d and since user told us not to print then.");
				}
				else
				{
					char * mem_p = mem_buf;
					unsigned long long offset = proc_pid_maps_item->start;
					
					// We are assuming memory 
					// regions are always a multiple 
					// of 16.
					while (mem_p < mem_buf + size)
					{
						printf(
							"%16llp"
							"   %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx"
							"   %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx %02hhx"
							"  |%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c|"
 							"   %s"
							"\n",
							offset,
							mem_p[0x0],
							mem_p[0x1],
							mem_p[0x2],
							mem_p[0x3],
							mem_p[0x4],
							mem_p[0x5],
							mem_p[0x6],
							mem_p[0x7],
							mem_p[0x8],
							mem_p[0x9],
							mem_p[0xa],
							mem_p[0xb],
							mem_p[0xc],
							mem_p[0xd],
							mem_p[0xe],
							mem_p[0xf],
							isprint(mem_p[0x0]) ? mem_p[0x0] : '.',
							isprint(mem_p[0x1]) ? mem_p[0x1] : '.',
							isprint(mem_p[0x2]) ? mem_p[0x2] : '.',
							isprint(mem_p[0x3]) ? mem_p[0x3] : '.',
							isprint(mem_p[0x4]) ? mem_p[0x4] : '.',
							isprint(mem_p[0x5]) ? mem_p[0x5] : '.',
							isprint(mem_p[0x6]) ? mem_p[0x6] : '.',
							isprint(mem_p[0x7]) ? mem_p[0x7] : '.',
							isprint(mem_p[0x8]) ? mem_p[0x8] : '.',
							isprint(mem_p[0x9]) ? mem_p[0x9] : '.',
							isprint(mem_p[0xa]) ? mem_p[0xa] : '.',
							isprint(mem_p[0xb]) ? mem_p[0xb] : '.',
							isprint(mem_p[0xc]) ? mem_p[0xc] : '.',
							isprint(mem_p[0xd]) ? mem_p[0xd] : '.',
							isprint(mem_p[0xe]) ? mem_p[0xe] : '.',
							isprint(mem_p[0xf]) ? mem_p[0xf] : '.',
							proc_pid_maps_item->pathname
						);
						mem_p += 16;
						offset += 16;
					}
				}
			}
		}
		
		if (options['s'].cptr != NULL)
		{
			if (options['f'].ull && proc_pid_maps_item->pathname[0] == '/')
			{
				log_debug2("Skipping memory region, since it is mmap()'d and since user told us not to print then.");
			}
			else
			{
				char * start = mem_buf;
				do
				{
					size_t len = size - (start - mem_buf);
					start = memmem(start, len, needle, needle_len);
					if (start)
					{
						log_debug("%p: %s (file: '%s')", start, needle, proc_pid_maps_item[0].pathname);
						++start;
					}
				} while (start != NULL);
			}
		}
		
		++proc_pid_maps_item;
	}
	
	close(mem_fd);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
	free(proc_pid_maps_items);
}



int main(int argc, char *argv[], char **envp)
{
	char const * const short_options = "dfs:v";
	struct option long_options[] =
	{
		{"dump",	no_argument,		NULL,	'd'},
		{"no-files",	no_argument,		NULL,	'f'},
		{"hexdump",	no_argument,		NULL,	'h'},
		{"search",	required_argument,	NULL,	's'},
		{"verbose",	no_argument,		NULL,	'v'},
	};
	
	static struct option_tt
	{
		union
		{
			unsigned long long ull;
			char * cptr;
		};
	} options[256];
	
	while (1)
	{
		log_debug2("Parsing command line arguments.");
		int option_index = 0;
		int opt = getopt_long(
			argc,
			argv,
			short_options,
			long_options,
			&option_index
		);
		
		if (opt == -1)
		{
			// No more options, i.e. parsed all options.
			break;
		}
		
		switch (opt)
		{
			case 0: // Long option.
				log_debug2("Option: %s", long_options[option_index].name);
				break;
			
			case 'd': // Dump
			case 'f': // Don't handle mmap'd files.
			case 'h': // Hexdump
				log_debug2("???");
				options[opt].ull = 1;
				break;
			
			/* Search. */
			case 's':
				options[opt].cptr = strdup(optarg);
				break;
			
			case 'v':
				++verbosity;
				break;
			
			case '?':
			default:
				log_error("Unknown return code from getopt_long: %d", opt);
		}
	}
	log_debug2("Done parsing command line arguments.");
	
	if (optind >= argc)
	{
		log_error("First argument must be a PID.");
		return 1;
	}
	int pid = atoi(argv[optind++]);
	if (pid == 0)
	{
		log_error("Could not convert '%s' to integer.", argv[1]);
		return 5;
	}
	
	read_proc_pid_mem(pid, options);
	
	free(options['s'].cptr);	// Was strdup()'d.
	
	return 0;
}