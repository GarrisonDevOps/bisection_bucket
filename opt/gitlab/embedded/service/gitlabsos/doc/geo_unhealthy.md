# Geo nodes shown as unhealthy

#### Before beginning

- Review the output of `sudo gitlab-rake gitlab:geo:check` on both the primary
and secondary to see if there's anything obvious being found.

- Read through the [Geo troubleshooting](https://docs.gitlab.com/ee/administration/geo/replication/troubleshooting.html) 
steps to see if anything here applies.

- The command `gitlab-psql -c 'select * from PG_STAT_REPLICATION'` can also tell us a lot but the information
should be similar to what we can see in `ps` below.

## What to look for in the GitLabSOS

#### Logs of interest

Related geo errors will be found in `var/log/gitlab/gitlab-rails/geo.log`.  To see all errors in this file
query with `jq 'select(.severity == "ERROR") | .' geo.log`.

To see a quick snapshot of all error messages in this log grouped together try
`jq 'select(.severity == "ERROR") | .error' geo.log | sort -n | uniq -c`.

Geo depends on PostgreSQL replication so the `var/log/gitlab/postgresql/current` 
and `var/log/gitlab/geo-postgresql/current` may also be of interest.

#### Check the running processes on both primary and secondary.  

These can be found in the `ps` file.

Geo uses streaming replication.  A `grep postgres ps` on primary should look like:

```
root         330  0.0  0.0   2380   700 ?        Ss   08:24   0:00 runsv postgresql
root         334  0.0  0.0   2524   640 ?        S    08:24   0:00 svlogd -tt /var/log/gitlab/postgresql
gitlab-+     339  0.1  0.3  50324 29356 ?        Ss   08:24   0:00 /opt/gitlab/embedded/bin/postgres -D /var/opt/gitlab/postgresql/data
gitlab-+     384  0.0  0.0  50324  3668 ?        Ss   08:24   0:00 postgres: checkpointer
gitlab-+     385  0.0  0.0  50516  5448 ?        Ss   08:24   0:00 postgres: background writer
gitlab-+     386  0.0  0.0  50324  3668 ?        Ss   08:24   0:00 postgres: walwriter
gitlab-+     387  0.0  0.0  51132  6184 ?        Ss   08:24   0:00 postgres: autovacuum launcher
gitlab-+     388  0.0  0.0  17848  3856 ?        Ss   08:24   0:00 postgres: stats collector
gitlab-+     389  0.0  0.0  51080  6032 ?        Ss   08:24   0:00 postgres: logical replication launcher
gitlab-+     418  0.1  0.1  51688 11356 ?        Ss   08:24   0:00 postgres: walsender gitlab_replicator 34.138.215.40(41950) streaming 0/FD09810
gitlab-+     465  1.7  0.3  59832 24832 ?        Ss   08:24   0:00 postgres: gitlab gitlabhq_production 127.0.0.1(48948) idle
gitlab-+     475 11.6  0.5  90312 47696 ?        Ss   08:24   0:00 postgres: gitlab-psql gitlabhq_production [local] idle
gitlab-+     476  0.6  0.1  53360 13628 ?        Ss   08:24   0:00 postgres: gitlab-psql gitlabhq_production [local] idle
```

The same on secondary should look like:

```
root         289  0.0  0.0   2380   696 ?        Ss   08:24   0:00 runsv postgresql
root         301  0.0  0.0   2524   696 ?        S    08:24   0:00 svlogd -tt /var/log/gitlab/postgresql
gitlab-+     308  0.1  0.3  50324 29432 ?        Ss   08:24   0:00 /opt/gitlab/embedded/bin/postgres -D /var/opt/gitlab/postgresql/data
gitlab-+     355  0.5  0.0  50472  6584 ?        Ss   08:24   0:00 postgres: startup recovering 00000001000000000000000F
gitlab-+     357  0.0  0.0  50324  3744 ?        Ss   08:24   0:00 postgres: checkpointer
gitlab-+     358  0.0  0.0  50324  3624 ?        Ss   08:24   0:00 postgres: background writer
gitlab-+     359  0.0  0.0  17848  4812 ?        Ss   08:24   0:00 postgres: stats collector
gitlab-+     360  0.1  0.1  51336 10272 ?        Ss   08:24   0:00 postgres: walreceiver streaming 0/FD09810
root         441  0.0  0.0   2380   636 ?        Ss   08:24   0:00 runsv geo-postgresql
root         442  0.0  0.0   2524   636 ?        S    08:24   0:00 svlogd -tt /var/log/gitlab/geo-postgresql
gitlab-+     443  0.1  0.8 1139460 65340 ?       Ss   08:24   0:00 /opt/gitlab/embedded/bin/postgres -D /var/opt/gitlab/geo-postgresql/data
gitlab-+     445  0.0  0.0 1139460 2956 ?        Ss   08:24   0:00 postgres: checkpointer
gitlab-+     446  0.0  0.0 1139460 5804 ?        Ss   08:24   0:00 postgres: background writer
gitlab-+     447  0.0  0.0 1139460 2956 ?        Ss   08:24   0:00 postgres: walwriter
gitlab-+     448  0.0  0.0 1140284 5516 ?        Ss   08:24   0:00 postgres: autovacuum launcher
gitlab-+     449  0.0  0.0  16876  3716 ?        Ss   08:24   0:00 postgres: stats collector
gitlab-+     450  0.0  0.0 1140244 5860 ?        Ss   08:24   0:00 postgres: logical replication launcher
gitlab-+     468  0.7  0.3  60652 25112 ?        Ss   08:24   0:00 postgres: gitlab gitlabhq_production 127.0.0.1(59668) idle
gitlab-+     476  2.2  0.5  91720 48796 ?        Ss   08:24   0:00 postgres: gitlab-psql gitlabhq_production [local] idle
gitlab-+     477  0.2  0.1  53372 14548 ?        Ss   08:24   0:00 postgres: gitlab-psql gitlabhq_production [local] idle
``` 

Also check how much CPU (3rd column) is being utilized by these processes.  It can tell us how hard Geo is working.

#### Check Sidekiq jobs

Geo depends on Sidekiq jobs for a number of different things, even updating the status.

Try running [fast-stats](https://gitlab.com/gitlab-com/support/toolbox/fast-stats) against `var/log/gitlab/sidekiq/current`
to see the overall health and which jobs are taking however long.

Also try using the plot feature with `faststats plot var/log/gitlab/sidekiq/current`.

Any sort of spikes are of a concern.  A common one is long queue durations which indicate Sidekiq has been overwhelmed and is falling behind. 
