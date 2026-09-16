//! Background jobs, run on a cron schedule inside the server (UTC).

pub mod purge;

use std::sync::Arc;

use tokio_cron_scheduler::Job;
use tokio_cron_scheduler::JobScheduler;
use tokio_cron_scheduler::JobSchedulerError;

use crate::db::DbPool;
use crate::master_key::MasterKey;
use crate::signing_keys::SharedSigningKeys;
use crate::signing_keys::{self};

// sec min hour day month weekday — minutes chosen away from the busy top of the hour.
/// Every hour at :17.
const PURGE_SCHEDULE: &str = "0 17 * * * *";
/// Every hour at :07: picks up keys published or retired by any instance.
const RELOAD_KEYS_SCHEDULE: &str = "0 7 * * * *";
/// Every day at 03:23.
const ROTATE_KEYS_SCHEDULE: &str = "0 23 3 * * *";

/// Starts the scheduler. Keep the returned value alive for as long as jobs should run.
pub async fn start(
    db: DbPool,
    master_key: Arc<MasterKey>,
    keys: SharedSigningKeys,
) -> Result<JobScheduler, JobSchedulerError> {
    let scheduler = JobScheduler::new().await?;

    let purge_db = db.clone();
    scheduler
        .add(Job::new_async(PURGE_SCHEDULE, move |_id, _scheduler| {
            let db = purge_db.clone();
            Box::pin(async move {
                match purge::run(&db).await {
                    Ok(Some(report)) => report.log(),
                    Ok(None) => tracing::debug!("purge skipped: another instance is running it"),
                    Err(error) => tracing::error!(%error, "purge failed"),
                }
            })
        })?)
        .await?;

    let (reload_db, reload_master_key, reload_keys) =
        (db.clone(), master_key.clone(), keys.clone());
    scheduler
        .add(Job::new_async(
            RELOAD_KEYS_SCHEDULE,
            move |_id, _scheduler| {
                let (db, master_key, keys) = (
                    reload_db.clone(),
                    reload_master_key.clone(),
                    reload_keys.clone(),
                );
                Box::pin(async move {
                    if let Err(error) = signing_keys::reload(&db, &master_key, &keys).await {
                        tracing::error!(%error, "signing keys reload failed");
                    }
                })
            },
        )?)
        .await?;

    scheduler
        .add(Job::new_async(
            ROTATE_KEYS_SCHEDULE,
            move |_id, _scheduler| {
                let (db, master_key, keys) = (db.clone(), master_key.clone(), keys.clone());
                Box::pin(async move {
                    match signing_keys::rotate_if_due(&db, &master_key).await {
                        // Load it right away here; other instances get it at their next hourly reload,
                        // well within the prepublication period.
                        Ok(Some(_)) => {
                            if let Err(error) = signing_keys::reload(&db, &master_key, &keys).await
                            {
                                tracing::error!(%error, "signing keys reload failed");
                            }
                        }
                        Ok(None) => tracing::debug!("no signing key rotation due"),
                        Err(error) => tracing::error!(%error, "signing key rotation failed"),
                    }
                })
            },
        )?)
        .await?;

    scheduler.start().await?;
    Ok(scheduler)
}
