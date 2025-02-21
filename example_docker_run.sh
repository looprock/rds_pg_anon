#!/bin/bash

if [ ! -d "${HOME}/pg_anon/data" ]; then
    mkdir -p "${HOME}/pg_anon/data"
fi

if [ ! -d "${HOME}/pg_anon/extend" ]; then
    mkdir -p "${HOME}/pg_anon/extend"
fi

docker run \
-v ${HOME}/pg_anon/data:/app/data \
-v ${HOME}/pg_anon/extend:/app/extend \
-v ${HOME}/.aws:/root/.aws \
-e PGDATABASE=${PGDATABASE} \
-e PGPORT=${PGPORT} \
-e PGUSER=${PGUSER} \
-e PGANON_S3_BUCKET_NAME=${PGANON_S3_BUCKET_NAME} \
-e PGANON_ENVIRONMENT=${PGANON_ENVIRONMENT} \
-e PGANON_RDS_VPCSECURITYGROUPIDS=${PGANON_RDS_VPCSECURITYGROUPIDS} \
-e PGANON_RDS_DBSUBNETGROUPNAME=${PGANON_RDS_DBSUBNETGROUPNAME} \
-e PGANON_RDS_SOURCE_ID=${PGANON_RDS_SOURCE_ID} \
-e PGPASSWORD=${PGPASSWORD} \
-e PGANON_SAVE_DB=${PGANON_SAVE_DB} \
-e PGANON_SECRET_PROFILE=${PGANON_SECRET_PROFILE} \
-e AWS_PROFILE=${AWS_PROFILE} \
ghcr.io/looprock/rds_pg_anon:test1 \
--dry-run
