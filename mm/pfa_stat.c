#include <linux/pfa_stat.h>
#include <linux/kobject.h>
#include <linux/slab.h>

pfa_stat_t pfa_stats = {0};
struct task_struct *pfa_stat_tsk = NULL;
uint64_t pfa_pfstart = 0;
uintptr_t pfa_last_vaddr = 0;

/* Generic stats and profiling for the PFA and swapping subsystem. Works for
 * both the baseline and the PFA (not sure about validity for rswap-only...).
 */
ssize_t pfa_sysfs_show_stat(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_stat(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

/* This prints a csv header row for the PFA stats, this makes it easy to dump
 * csvs (call this once and then read from pfa_stat a bunch of times for
 * different experiments */
ssize_t pfa_sysfs_show_statlbl(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_statlbl(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

/* This supports the page-fault latency experiment which requires a special
 * user-space program to cooperate. */
ssize_t pfa_sysfs_show_pflat(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_pflat(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

struct kobj_attribute pfa_sysfs_stat = __ATTR(pfa_stat, 0660, pfa_sysfs_show_stat, pfa_sysfs_store_stat);
struct kobj_attribute pfa_sysfs_statlbl = __ATTR(pfa_stat_label, 0660, pfa_sysfs_show_statlbl, pfa_sysfs_store_statlbl);
struct kobj_attribute pfa_sysfs_pflat = __ATTR(pfa_pflat, 0660, pfa_sysfs_show_pflat, pfa_sysfs_store_pflat);

void pfa_stat_init(void)
{
  printk("loading pfa_stat\n");
  if(sysfs_create_file(mm_kobj, &pfa_sysfs_stat.attr) != 0)
    pr_err("Failed to create sysfs entries for pfa statistics\n");
  if(sysfs_create_file(mm_kobj, &pfa_sysfs_statlbl.attr) != 0)
    pr_err("Failed to create sysfs entries for pfa statistics\n");

#ifdef CONFIG_PFA_PFLAT  
  if(sysfs_create_file(mm_kobj, &pfa_sysfs_pflat.attr) != 0)
    pr_err("Failed to create sysfs entries for pfa \"page-fault latency\" experiment\n");
#endif
}

static const pfa_stat_t __pfa_stat_empty = {0};
void pfa_stat_reset(struct task_struct *tsk)
{
  pfa_stats = __pfa_stat_empty;
  pfa_stat_tsk = tsk;
  pfa_stat_set(t_start, pfa_stat_clock(), tsk);
}

ssize_t pfa_sysfs_show_stat(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
  /* STOP!!!!
   * STOP!!!!
   * STOP!!!!
   * STOP!!!!
   * Don't change this without changing pfa_sysfs_show_statlbl!!!!
   * OK, you may continue.
   */
  return sprintf(buf,
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld,"
      "%ld\n",
      atomic64_read(&pfa_stats.t_run),
      atomic64_read(&pfa_stats.t_bookkeeping),
      atomic64_read(&pfa_stats.t_rmem_write),
      atomic64_read(&pfa_stats.t_rmem_read),
      atomic64_read(&pfa_stats.n_fault),
      atomic64_read(&pfa_stats.t_fault),
      atomic64_read(&pfa_stats.n_swapfault),
      atomic64_read(&pfa_stats.n_pfa_fault),
      atomic64_read(&pfa_stats.n_early_newq),
      atomic64_read(&pfa_stats.n_evicted),
      atomic64_read(&pfa_stats.n_fetched),
      atomic64_read(&pfa_stats.n_kpfad),
      atomic64_read(&pfa_stats.t_kpfad));
}

static ssize_t pfa_sysfs_store_stat(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count)
{
  pid_t pid;
  struct task_struct *tsk = NULL;
  if(kstrtoint(buf, 10, &pid) == 0) {
    tsk = find_task_by_vpid(pid);
  }

  pfa_stat_reset(tsk);
 
  return count;
}

ssize_t pfa_sysfs_show_statlbl(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
  return sprintf(buf,
      "t_run,"
      "t_bookkeeping,"
      "t_rmem_write,"
      "t_rmem_read,"
      "n_fault,"
      "t_fault,"
      "n_swapfault,"
      "n_pfa_fault,"
      "n_early_newq,"
      "n_evicted,"
      "n_fetched,"
      "n_kpfad,"
      "t_kpfad\n");
}

static ssize_t pfa_sysfs_store_statlbl(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count)
{
  return 0;
}

/* state 0: recording evicted pages
   state 1: recording page-fault start times (to measure trap) */
int pfa_pflat_state = 0;
ssize_t pfa_sysfs_show_pflat(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf)
{
  if(pfa_pflat_state == 0) {
    pfa_pflat_state = 1;
    return sprintf(buf, "0x%lx", pfa_last_vaddr);
  } else if(pfa_pflat_state == 1) {
    pfa_pflat_state = 0;
    pfa_stat_tsk = NULL;
    return sprintf(buf, "%llu", pfa_pfstart);
  } else {
    printk("pflat: invalid state %d\n", pfa_pflat_state);
    return 0;
  }
}

static ssize_t pfa_sysfs_store_pflat(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count)
{
  pfa_pflat_state = 0;
  pfa_pfstart = 0;
  pfa_last_vaddr = 0;
  pfa_stat_tsk = current;
  return count;
}
