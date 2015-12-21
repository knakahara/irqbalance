/* 
 * Copyright (C) 2006, Intel Corporation
 * Copyright (C) 2012, Neil Horman <nhorman@tuxdriver.com> 
 * 
 * This file is part of irqbalance
 *
 * This program file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; version 2 of the License.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program in a file named COPYING; if not, write to the 
 * Free Software Foundation, Inc., 
 * 51 Franklin Street, Fifth Floor, 
 * Boston, MA 02110-1301 USA
 */

/* 
 * This file contains the code to communicate a selected distribution / mapping
 * of interrupts to the kernel.
 */
#ifdef __NetBSD__
#include <sys/param.h>
#include <sys/sysctl.h>
#include <stdbool.h>
#include <err.h>
#undef ALIGN
#endif
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "irqbalance.h"
#ifdef __NetBSD__
#include "intrctl_io.h"
#endif

static int intrctl_io_alloc_retry_count = 4;

static int check_affinity(struct irq_info *info, cpumask_t applied_mask)
{
	cpumask_t current_mask;
#ifdef __NetBSD__
	void *handle;
	struct intrio_list_line *illine;
	int i, ncpu, assigned = -1;
#else
	char buf[PATH_MAX];
	char *line = NULL;
	size_t size = 0;
	FILE *file;
#endif

#ifdef __NetBSD__
	handle = intrctl_io_alloc(intrctl_io_alloc_retry_count);
	if (handle == NULL)
		err(EXIT_FAILURE, "intrctl_io_alloc");

	ncpu = intrctl_io_ncpus(handle);
	illine = intrctl_io_firstline(handle);
	for (; illine != NULL; illine = intrctl_io_nextline(handle, illine)) {
		if (strncmp(info->name, illine->ill_intrid, sizeof(illine->ill_intrid)) == 0) {
			struct intrio_list_line_cpu *illcpu;
			illcpu = illine->ill_cpu;
			for (i = 0; i < ncpu; i++) {
				if (illcpu[i].illc_assigned)
					assigned = i;
			}
		}
	}
	cpus_clear(current_mask);
	cpu_set(assigned, current_mask);
#else
	sprintf(buf, "/proc/irq/%i/smp_affinity", info->irq);
	file = fopen(buf, "r");
	if (!file)
		return 1;
	if (getline(&line, &size, file)==0) {
		free(line);
		fclose(file);
		return 1;
	}
	cpumask_parse_user(line, strlen(line), current_mask);
	fclose(file);
	free(line);
#endif

	return cpus_equal(applied_mask, current_mask);
}

static void activate_mapping(struct irq_info *info, void *data __attribute__((unused)))
{
#ifdef __NetBSD__
	void *handle;
	cpuset_t *cpuset;
	struct intrio_set iset;
#else
	char buf[PATH_MAX];
	FILE *file;
#endif
	cpumask_t applied_mask;
	int valid_mask = 0;

	/*
 	 * only activate mappings for irqs that have moved
 	 */
	if (!info->moved)
		return;

	if ((info->hint_policy == HINT_POLICY_EXACT) &&
	    (!cpus_empty(info->affinity_hint))) {
		if (cpus_intersects(info->affinity_hint, banned_cpus))
			log(TO_ALL, LOG_WARNING,
			    "irq %d affinity_hint and banned cpus confict\n",
			    info->irq);
		else {
			applied_mask = info->affinity_hint;
			valid_mask = 1;
		}
	} else if (info->assigned_obj) {
		applied_mask = info->assigned_obj->mask;
		if ((info->hint_policy == HINT_POLICY_SUBSET) &&
		    (!cpus_empty(info->affinity_hint))) {
			cpus_and(applied_mask, applied_mask, info->affinity_hint);
			if (!cpus_intersects(applied_mask, unbanned_cpus)) {
				if (!info->warned) {
					info->warned = 1;
					log(TO_ALL, LOG_WARNING,
					    "irq %d affinity_hint subset empty\n",
					    info->irq);
				}
			} else
				valid_mask = 1;
		} else {
			valid_mask = 1;
		}
	}

	/*
 	 * Don't activate anything for which we have an invalid mask 
 	 */
	if (!valid_mask || check_affinity(info, applied_mask))
		return;

	if (!info->assigned_obj)
		return;


#ifdef __NetBSD__
	handle = intrctl_io_alloc(intrctl_io_alloc_retry_count);
	if (handle == NULL)
		err(EXIT_FAILURE, "intrctl_io_alloc");

	cpuset = cpuset_create();
	if (cpuset == NULL)
		err(EXIT_FAILURE, "create_cpuset()");

	strlcpy(iset.intrid, info->name, INTRIDBUF);

	cpuset_zero(cpuset);
	cpuset_set(first_cpu(applied_mask), cpuset);
	iset.cpuset = cpuset;
	iset.cpuset_size = cpuset_size(cpuset);
	if (sysctlbyname("kern.intr.affinity", NULL, NULL, &iset, sizeof(iset)) < 0)
		err(EXIT_FAILURE, "sysctl kern.intr.affinity");
	cpuset_destroy(cpuset);
#else
	sprintf(buf, "/proc/irq/%i/smp_affinity", info->irq);
	file = fopen(buf, "w");
	if (!file)
		return;

	cpumask_scnprintf(buf, PATH_MAX, applied_mask);
	fprintf(file, "%s", buf);
	fclose(file);
#endif

	info->moved = 0; /*migration is done*/
}

void activate_mappings(void)
{
	for_each_irq(NULL, activate_mapping, NULL);
}
