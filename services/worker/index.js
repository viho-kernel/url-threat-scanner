import pg from "pg";
import { createClient } from "redis";

import {
  inspectUrl
} from "./http-scanner.js";

import {
  ScanSecurityError
} from "./network-security.js";

const { Pool } = pg;

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;

const pendingQueue = "scan-jobs";
const processingQueue = "scan-jobs:processing";
const maximumAttempts = 3;

if (!databaseUrl || !redisUrl) {
  console.error(
    JSON.stringify({
      event: "configuration_invalid",
      error: "DATABASE_URL and REDIS_URL are required"
    })
  );

  process.exit(1);
}

const database = new Pool({
  connectionString: databaseUrl,
  max: 5
});

const redis = createClient({
  url: redisUrl
});

redis.on("error", (error) => {
  console.error(
    JSON.stringify({
      event: "redis_error",
      error: error.message
    })
  );
});

function safeErrorCode(error) {
  if (error instanceof ScanSecurityError) {
    return error.code;
  }

  if (error.message === "request_timeout") {
    return "request_timeout";
  }

  return "network_request_failed";
}

async function acknowledgeJob(scanId) {
  await redis.lRem(
    processingQueue,
    0,
    scanId
  );
}

async function requeueJob(scanId) {
  await redis
    .multi()
    .lRem(processingQueue, 0, scanId)
    .rPush(pendingQueue, scanId)
    .exec();
}

async function recoverInterruptedJobs() {
  const scanIds = await redis.lRange(
    processingQueue,
    0,
    -1
  );

  for (const scanId of new Set(scanIds)) {
    const result = await database.query(
      `UPDATE scans
       SET status = $1,
           error_message = $2,
           updated_at = NOW()
       WHERE id = $3
         AND status = $4
       RETURNING id`,
      [
        "queued",
        "worker_interrupted",
        scanId,
        "running"
      ]
    );

    if (result.rowCount === 1) {
      await requeueJob(scanId);

      console.warn(
        JSON.stringify({
          event: "interrupted_job_requeued",
          scan_id: scanId
        })
      );
    } else {
      await acknowledgeJob(scanId);
    }
  }
}

async function claimJob(scanId) {
  const result = await database.query(
    `UPDATE scans
     SET status = $1,
         started_at = NOW(),
         completed_at = NULL,
         error_message = NULL,
         worker_attempts = worker_attempts + 1,
         updated_at = NOW()
     WHERE id = $2
       AND status = $3
     RETURNING id, url, worker_attempts`,
    [
      "running",
      scanId,
      "queued"
    ]
  );

  return result.rows[0] ?? null;
}

async function completeJob(scanId, scanResult) {
  await database.query(
    `UPDATE scans
     SET status = $1,
         result = $2::jsonb,
         error_message = NULL,
         completed_at = NOW(),
         updated_at = NOW()
     WHERE id = $3
       AND status = $4`,
    [
      "completed",
      JSON.stringify(scanResult),
      scanId,
      "running"
    ]
  );

  await acknowledgeJob(scanId);
}

async function failOrRetryJob(
  job,
  errorCode,
  retryable
) {
  if (
    retryable &&
    job.worker_attempts < maximumAttempts
  ) {
    await database.query(
      `UPDATE scans
       SET status = $1,
           error_message = $2,
           updated_at = NOW()
       WHERE id = $3
         AND status = $4`,
      [
        "queued",
        errorCode,
        job.id,
        "running"
      ]
    );

    await requeueJob(job.id);

    console.warn(
      JSON.stringify({
        event: "job_requeued",
        scan_id: job.id,
        attempt: job.worker_attempts,
        error: errorCode
      })
    );

    return;
  }

  await database.query(
    `UPDATE scans
     SET status = $1,
         error_message = $2,
         completed_at = NOW(),
         updated_at = NOW()
     WHERE id = $3
       AND status = $4`,
    [
      "failed",
      errorCode,
      job.id,
      "running"
    ]
  );

  await acknowledgeJob(job.id);

  console.error(
    JSON.stringify({
      event: "job_failed",
      scan_id: job.id,
      attempts: job.worker_attempts,
      error: errorCode
    })
  );
}

async function processJob(scanId) {
  const job = await claimJob(scanId);

  if (!job) {
    console.warn(
      JSON.stringify({
        event: "job_ignored",
        scan_id: scanId,
        reason: "scan missing or not queued"
      })
    );

    await acknowledgeJob(scanId);
    return;
  }

  console.log(
    JSON.stringify({
      event: "job_claimed",
      scan_id: job.id,
      attempt: job.worker_attempts
    })
  );

  try {
    const scanResult = await inspectUrl(job.url);

    await completeJob(
      job.id,
      scanResult
    );

    console.log(
      JSON.stringify({
        event: "job_completed",
        scan_id: job.id,
        verdict: scanResult.verdict,
        risk_score: scanResult.risk_score
      })
    );
  } catch (error) {
    const errorCode = safeErrorCode(error);

    const retryable =
      !(error instanceof ScanSecurityError);

    await failOrRetryJob(
      job,
      errorCode,
      retryable
    );
  }
}

async function run() {
  await redis.connect();
  await database.query("SELECT 1");

  await recoverInterruptedJobs();

  console.log(
    JSON.stringify({
      event: "worker_ready",
      queue: pendingQueue
    })
  );

  while (true) {
    const scanId = await redis.sendCommand([
      "BRPOPLPUSH",
      pendingQueue,
      processingQueue,
      "0"
    ]);

    if (scanId) {
      await processJob(scanId);
    }
  }
}

run().catch((error) => {
  console.error(
    JSON.stringify({
      event: "worker_failed",
      error: safeErrorCode(error)
    })
  );

  process.exit(1);
});