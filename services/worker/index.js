import pg from "pg";
import { createClient } from "redis";

const { Pool } = pg;

const databaseUrl = process.env.DATABASE_URL;
const redisUrl = process.env.REDIS_URL;

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

async function run() {
  await redis.connect();
  await database.query("SELECT 1");

  console.log(
    JSON.stringify({
      event: "worker_ready",
      queue: "scan-jobs"
    })
  );

  while (true) {
    /*
     * Wait for a job and atomically move it:
     *
     * scan-jobs → scan-jobs:processing
     *
     * The job is therefore not silently lost if the worker crashes.
     */
    const scanId = await redis.sendCommand([
      "BRPOPLPUSH",
      "scan-jobs",
      "scan-jobs:processing",
      "0"
    ]);

    if (!scanId) {
      continue;
    }

    try {
      const result = await database.query(
        `UPDATE scans
         SET status = $1,
             updated_at = NOW()
         WHERE id = $2
           AND status = $3
         RETURNING id`,
        ["running", scanId, "queued"]
      );

      if (result.rowCount === 0) {
        console.warn(
          JSON.stringify({
            event: "job_ignored",
            scan_id: scanId,
            reason: "scan missing or not queued"
          })
        );

        await redis.lRem("scan-jobs:processing", 1, scanId);
        continue;
      }

      console.log(
        JSON.stringify({
          event: "job_claimed",
          scan_id: scanId,
          status: "running"
        })
      );
    } catch (error) {
      console.error(
        JSON.stringify({
          event: "job_claim_failed",
          scan_id: scanId,
          error: error.message
        })
      );

      // Return the job to the queue so it can be retried.
      await redis.lRem("scan-jobs:processing", 1, scanId);
      await redis.rPush("scan-jobs", scanId);
    }
  }
}

run().catch((error) => {
  console.error(
    JSON.stringify({
      event: "worker_failed",
      error: error.message
    })
  );

  process.exit(1);
});