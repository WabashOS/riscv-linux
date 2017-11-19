#include <linux/pfa_stat.h>
#include <linux/kobject.h>

pfa_stat_t pfa_stats = {0};
struct task_struct *pfa_stat_tsk = NULL;

ssize_t pfa_sysfs_show_stat(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_stat(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

ssize_t pfa_sysfs_show_statlbl(struct kobject *kobj,
    struct kobj_attribute *attr, char *buf);
static ssize_t pfa_sysfs_store_statlbl(struct kobject *kobj,
    struct kobj_attribute *attr, const char *buf, size_t count);

struct kobj_attribute pfa_sysfs_stat = __ATTR(pfa_stat, 0660, pfa_sysfs_show_stat, pfa_sysfs_store_stat);
struct kobj_attribute pfa_sysfs_statlbl = __ATTR(pfa_stat_label, 0660, pfa_sysfs_show_statlbl, pfa_sysfs_store_statlbl);

void pfa_stat_init(void)
{
  if(sysfs_create_file(mm_kobj, &pfa_sysfs_stat.attr) != 0)
    pr_err("Failed to create sysfs entries for pfa statistics\n");
  if(sysfs_create_file(mm_kobj, &pfa_sysfs_statlbl.attr) != 0)
    pr_err("Failed to create sysfs entries for pfa statistics\n");
}

static const pfa_stat_t __pfa_stat_empty = {0};
void pfa_stat_reset(struct task_struct *tsk)
{
  pfa_stats = __pfa_stat_empty;
  pfa_stat_tsk = tsk;
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
      "%ld\n",
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
