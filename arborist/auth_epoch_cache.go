package arborist

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jmoiron/sqlx"
	redis "github.com/redis/go-redis/v9"
)

const (
	authzEpochRedisGlobalKey        = "authz:epoch:global"
	authzEpochRedisSubjectKeyPrefix = "authz:epoch:subject:"
)

type authzEpochTouchSet struct {
	globalIncrements int64
	subjects         map[string]int64
}

type authzEpochRedisStore struct {
	client *redis.Client
	logger Logger
}

var authzEpochTouchRegistry = struct {
	mu   sync.Mutex
	sets map[*sqlx.Tx]*authzEpochTouchSet
}{
	sets: map[*sqlx.Tx]*authzEpochTouchSet{},
}

var authzEpochRedis *authzEpochRedisStore

func configureAuthzEpochRedis(logger Logger) {
	redisURL := strings.TrimSpace(os.Getenv("AUTHZ_SNAPSHOT_CACHE_REDIS_URL"))
	if redisURL == "" {
		redisURL = strings.TrimSpace(os.Getenv("REDIS_URL"))
	}
	if password := strings.TrimSpace(os.Getenv("AUTHZ_SNAPSHOT_CACHE_REDIS_PASSWORD")); redisURL != "" && password != "" && strings.HasPrefix(redisURL, "redis://") && !strings.Contains(redisURL, "@") {
		redisURL = "redis://:" + password + "@" + strings.TrimPrefix(redisURL, "redis://")
	}
	if redisURL == "" {
		return
	}
	options, err := redis.ParseURL(redisURL)
	if err != nil {
		if logger != nil {
			logger.Warning("failed to parse authz snapshot redis url: %s", err.Error())
		}
		return
	}
	client := redis.NewClient(options)
	authzEpochRedis = &authzEpochRedisStore{client: client, logger: logger}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Ping(ctx).Err(); err != nil {
		if logger != nil {
			logger.Warning("authz epoch redis configured but initial ping failed; epoch sync will retry on mutation: %s", err.Error())
		}
		return
	}
	if logger != nil {
		logger.Info("Authz epoch redis synchronization enabled.")
	}
}

func authzSubjectEpochRedisKey(subjectType string, subjectName string) string {
	return authzEpochRedisSubjectKeyPrefix + strings.TrimSpace(subjectType) + ":" + strings.ToLower(strings.TrimSpace(subjectName))
}

func authzEpochTouchesForTx(tx *sqlx.Tx) *authzEpochTouchSet {
	authzEpochTouchRegistry.mu.Lock()
	defer authzEpochTouchRegistry.mu.Unlock()
	touches, ok := authzEpochTouchRegistry.sets[tx]
	if !ok {
		touches = &authzEpochTouchSet{subjects: map[string]int64{}}
		authzEpochTouchRegistry.sets[tx] = touches
	}
	return touches
}

func popAuthzEpochTouches(tx *sqlx.Tx) *authzEpochTouchSet {
	authzEpochTouchRegistry.mu.Lock()
	defer authzEpochTouchRegistry.mu.Unlock()
	touches := authzEpochTouchRegistry.sets[tx]
	delete(authzEpochTouchRegistry.sets, tx)
	return touches
}

func registerGlobalAuthzEpochTouch(tx *sqlx.Tx) {
	touches := authzEpochTouchesForTx(tx)
	touches.globalIncrements++
}

func registerSubjectAuthzEpochTouch(tx *sqlx.Tx, subjectType string, subjectName string) {
	subjectType = strings.TrimSpace(subjectType)
	subjectName = strings.ToLower(strings.TrimSpace(subjectName))
	if subjectType == "" || subjectName == "" {
		return
	}
	touches := authzEpochTouchesForTx(tx)
	touches.subjects[authzSubjectEpochRedisKey(subjectType, subjectName)]++
}

func syncCommittedAuthzEpochTouches(touches *authzEpochTouchSet) {
	if touches == nil {
		return
	}
	if authzEpochRedis == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pipe := authzEpochRedis.client.Pipeline()
	if touches.globalIncrements > 0 {
		pipe.IncrBy(ctx, authzEpochRedisGlobalKey, touches.globalIncrements)
	}
	for key, count := range touches.subjects {
		if count <= 0 {
			continue
		}
		pipe.IncrBy(ctx, key, count)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		if authzEpochRedis.logger != nil {
			authzEpochRedis.logger.Warning("failed to sync authz epochs to redis: %s", err.Error())
		}
		return
	}
	if authzEpochRedis.logger != nil {
		authzEpochRedis.logger.Info(
			"Synced authz epochs to redis: global_increments=%d subject_keys=%d",
			touches.globalIncrements,
			len(touches.subjects),
		)
	}
}
