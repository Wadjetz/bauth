use std::time::Duration;

use sqlx::migrate::MigrateError;
use sqlx::postgres::PgPoolOptions;

pub type Db = sqlx::Postgres;
pub type DbPool = sqlx::Pool<Db>;
pub type DbConnection = <Db as sqlx::Database>::Connection;

pub async fn connect(database_url: &str) -> Result<DbPool, sqlx::Error> {
    PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(database_url)
        .await
}

pub async fn migrate(pool: &DbPool) -> Result<(), MigrateError> {
    sqlx::migrate!().run(pool).await
}
