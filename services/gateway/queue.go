package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

type jobQueue struct {
	client *redis.Client
}

func openQueue() (*jobQueue, error) {
	redisAddress := os.Getenv("REDIS_ADDR")
	if redisAddress == "" {
		return nil, errors.New("REDIS_ADDR is required")
	}

	client := redis.NewClient(&redis.Options{
		Addr:         redisAddress,
		DialTimeout:  3 * time.Second,
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		client.Close()
		return nil, err
	}

	return &jobQueue{client: client}, nil
}

func (queue *jobQueue) ping(ctx context.Context) error {
	return queue.client.Ping(ctx).Err()
}

func (queue *jobQueue) close() error {
	return queue.client.Close()
}

func (queue *jobQueue) enqueue(
	ctx context.Context,
	scanID string,
) error {
	return queue.client.LPush(
		ctx,
		"scan-jobs",
		scanID,
	).Err()
}
