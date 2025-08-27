package cmgs3

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/sam-lord/certmagic"
)

const (
	testEndpoint  = "play.min.io"
	testBucket    = "certmagic-test-bucket"
	testPrefix    = "test-certs"
	testAccessKey = "Q3AM3UQ867SPQQA43P2F"
	testSecretKey = "zuf+tfteSlswRu7BJ86wekitnifILbZam1KYY3TG"
)

func TestS3StorageImplementsCertmagicStorage(t *testing.T) {
	var _ certmagic.Storage = (*S3Storage)(nil)
}

func setupTestStorage(t *testing.T, withEncryption bool) *S3Storage {
	opts := S3Opts{
		Endpoint:        testEndpoint,
		Bucket:          testBucket,
		AccessKeyID:     testAccessKey,
		SecretAccessKey: testSecretKey,
		ObjPrefix:       testPrefix,
	}

	if withEncryption {
		opts.EncryptionKey = []byte("12345678901234567890123456789012")
	}

	storage, err := NewS3Storage(opts)
	if err != nil {
		t.Skipf("Skipping test due to S3 setup error: %v", err)
	}

	ctx := context.Background()
	testCleanup(ctx, storage)

	return storage
}

func testCleanup(ctx context.Context, storage *S3Storage) {
	keys, _ := storage.List(ctx, "", true)
	for _, key := range keys {
		storage.Delete(ctx, key)
	}
}

func TestNewS3Storage(t *testing.T) {
	tests := []struct {
		name    string
		opts    S3Opts
		wantErr bool
	}{
		{
			name: "valid config without encryption",
			opts: S3Opts{
				Endpoint:        testEndpoint,
				Bucket:          testBucket,
				AccessKeyID:     testAccessKey,
				SecretAccessKey: testSecretKey,
				ObjPrefix:       testPrefix,
			},
			wantErr: false,
		},
		{
			name: "valid config with encryption",
			opts: S3Opts{
				Endpoint:        testEndpoint,
				Bucket:          testBucket,
				AccessKeyID:     testAccessKey,
				SecretAccessKey: testSecretKey,
				ObjPrefix:       testPrefix,
				EncryptionKey:   []byte("12345678901234567890123456789012"),
			},
			wantErr: false,
		},
		{
			name: "invalid encryption key length",
			opts: S3Opts{
				Endpoint:        testEndpoint,
				Bucket:          testBucket,
				AccessKeyID:     testAccessKey,
				SecretAccessKey: testSecretKey,
				ObjPrefix:       testPrefix,
				EncryptionKey:   []byte("short"),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage, err := NewS3Storage(tt.opts)
			if tt.wantErr {
				if err == nil {
					t.Errorf("NewS3Storage() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Skipf("Skipping test due to S3 setup error: %v", err)
			}
			if storage == nil {
				t.Errorf("NewS3Storage() returned nil storage")
			}
		})
	}
}

func TestS3Storage_StoreAndLoad(t *testing.T) {
	tests := []struct {
		name           string
		withEncryption bool
	}{
		{"cleartext", false},
		{"encrypted", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			storage := setupTestStorage(t, tt.withEncryption)
			ctx := context.Background()

			testKey := "test/certificate.pem"
			testValue := []byte("-----BEGIN CERTIFICATE-----\ntest certificate data\n-----END CERTIFICATE-----")

			err := storage.Store(ctx, testKey, testValue)
			if err != nil {
				t.Fatalf("Store() failed: %v", err)
			}

			loadedValue, err := storage.Load(ctx, testKey)
			if err != nil {
				t.Fatalf("Load() failed: %v", err)
			}

			if string(loadedValue) != string(testValue) {
				t.Errorf("Load() returned different value than stored. Expected: %s, Got: %s", testValue, loadedValue)
			}
		})
	}
}

func TestS3Storage_Exists(t *testing.T) {
	storage := setupTestStorage(t, false)
	ctx := context.Background()

	testKey := "test/exists.pem"

	if storage.Exists(ctx, testKey) {
		t.Errorf("Exists() returned true for non-existent key")
	}

	err := storage.Store(ctx, testKey, []byte("test data"))
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	if !storage.Exists(ctx, testKey) {
		t.Errorf("Exists() returned false for existing key")
	}
}

func TestS3Storage_Delete(t *testing.T) {
	storage := setupTestStorage(t, false)
	ctx := context.Background()

	testKey := "test/delete.pem"
	testValue := []byte("test data")

	err := storage.Store(ctx, testKey, testValue)
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	if !storage.Exists(ctx, testKey) {
		t.Errorf("Key should exist before deletion")
	}

	err = storage.Delete(ctx, testKey)
	if err != nil {
		t.Fatalf("Delete() failed: %v", err)
	}

	if storage.Exists(ctx, testKey) {
		t.Errorf("Key should not exist after deletion")
	}

	_, err = storage.Load(ctx, testKey)
	if err != fs.ErrNotExist {
		t.Errorf("Load() should return fs.ErrNotExist for deleted key, got: %v", err)
	}
}

func TestS3Storage_List(t *testing.T) {
	storage := setupTestStorage(t, false)
	ctx := context.Background()

	testKeys := []string{
		"test/cert1.pem",
		"test/cert2.pem",
		"test/key1.pem",
		"different/cert.pem",
	}

	for _, key := range testKeys {
		err := storage.Store(ctx, key, []byte(fmt.Sprintf("data for %s", key)))
		if err != nil {
			t.Fatalf("Store() failed for key %s: %v", key, err)
		}
	}

	keys, err := storage.List(ctx, "", true)
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	if len(keys) < len(testKeys) {
		t.Errorf("List() returned fewer keys than expected. Expected at least %d, got %d", len(testKeys), len(keys))
	}
}

func TestS3Storage_Stat(t *testing.T) {
	storage := setupTestStorage(t, false)
	ctx := context.Background()

	testKey := "test/stat.pem"
	testValue := []byte("test data for stat")

	_, err := storage.Stat(ctx, testKey)
	if err != fs.ErrNotExist {
		t.Errorf("Stat() should return fs.ErrNotExist for non-existent key, got: %v", err)
	}

	err = storage.Store(ctx, testKey, testValue)
	if err != nil {
		t.Fatalf("Store() failed: %v", err)
	}

	info, err := storage.Stat(ctx, testKey)
	if err != nil {
		t.Fatalf("Stat() failed: %v", err)
	}

	if info.Key != testKey {
		t.Errorf("Stat() returned wrong key. Expected: %s, Got: %s", testKey, info.Key)
	}

	if info.Size <= 0 {
		t.Errorf("Stat() returned invalid size: %d", info.Size)
	}

	if info.Modified.IsZero() {
		t.Errorf("Stat() returned zero modification time")
	}

	if !info.IsTerminal {
		t.Errorf("Stat() should mark file as terminal")
	}
}

func TestS3Storage_LockUnlock(t *testing.T) {
	storage := setupTestStorage(t, false)
	ctx := context.Background()

	testKey := "test/lock.pem"

	err := storage.Lock(ctx, testKey)
	if err != nil {
		t.Fatalf("Lock() failed: %v", err)
	}

	lockKey := storage.objLockName(testKey)
	if !storage.Exists(ctx, lockKey) {
		t.Errorf("Lock file should exist after locking")
	}

	err = storage.Unlock(ctx, testKey)
	if err != nil {
		t.Fatalf("Unlock() failed: %v", err)
	}
}

func TestS3Storage_LockTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping timeout test in short mode")
	}

	storage := setupTestStorage(t, false)
	ctx := context.Background()

	testKey := "test/timeout.pem"

	originalTimeout := LockTimeout
	LockTimeout = 2 * time.Second
	defer func() {
		LockTimeout = originalTimeout
	}()

	err := storage.Lock(ctx, testKey)
	if err != nil {
		t.Fatalf("First Lock() failed: %v", err)
	}

	start := time.Now()
	err = storage.Lock(ctx, testKey)
	duration := time.Since(start)

	if err == nil {
		t.Errorf("Second Lock() should have failed due to timeout")
		storage.Unlock(ctx, testKey)
		return
	}

	if duration < LockTimeout {
		t.Errorf("Lock() returned too quickly. Expected at least %v, got %v", LockTimeout, duration)
	}

	storage.Unlock(ctx, testKey)
}

func TestS3Storage_CertmagicCompatibility(t *testing.T) {
	storage := setupTestStorage(t, false)
	ctx := context.Background()

	testKeys := map[string][]byte{
		"certificates/example.com/example.com.crt": []byte("-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----"),
		"certificates/example.com/example.com.key": []byte("-----BEGIN PRIVATE KEY-----\ntest key\n-----END PRIVATE KEY-----"),
		"acme_accounts/letsencrypt.json":           []byte(`{"contact": ["mailto:test@example.com"]}`),
	}

	for key, value := range testKeys {
		err := storage.Store(ctx, key, value)
		if err != nil {
			t.Fatalf("Store() failed for certmagic key %s: %v", key, err)
		}

		if !storage.Exists(ctx, key) {
			t.Errorf("Key %s should exist after storage", key)
		}

		loadedValue, err := storage.Load(ctx, key)
		if err != nil {
			t.Fatalf("Load() failed for certmagic key %s: %v", key, err)
		}

		if string(loadedValue) != string(value) {
			t.Errorf("Loaded value differs for key %s", key)
		}

		info, err := storage.Stat(ctx, key)
		if err != nil {
			t.Fatalf("Stat() failed for certmagic key %s: %v", key, err)
		}

		if info.Key != key {
			t.Errorf("Stat() returned wrong key for %s", key)
		}
	}

	keys, err := storage.List(ctx, "", true)
	if err != nil {
		t.Fatalf("List() failed: %v", err)
	}

	if len(keys) < len(testKeys) {
		t.Errorf("List() should return at least %d keys, got %d", len(testKeys), len(keys))
	}
}

func TestS3Storage_EncryptionKeyValidation(t *testing.T) {
	tests := []struct {
		name        string
		encryptKey  []byte
		expectError bool
	}{
		{
			name:        "no encryption key",
			encryptKey:  nil,
			expectError: false,
		},
		{
			name:        "empty encryption key",
			encryptKey:  []byte{},
			expectError: false,
		},
		{
			name:        "valid 32-byte key",
			encryptKey:  []byte("12345678901234567890123456789012"),
			expectError: false,
		},
		{
			name:        "invalid key length - too short",
			encryptKey:  []byte("short"),
			expectError: true,
		},
		{
			name:        "invalid key length - too long",
			encryptKey:  []byte("123456789012345678901234567890123"),
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := S3Opts{
				Endpoint:        testEndpoint,
				Bucket:          testBucket,
				AccessKeyID:     testAccessKey,
				SecretAccessKey: testSecretKey,
				ObjPrefix:       testPrefix,
				EncryptionKey:   tt.encryptKey,
			}

			_, err := NewS3Storage(opts)
			if tt.expectError && err == nil {
				t.Errorf("Expected error for invalid encryption key, but got none")
			}
			if !tt.expectError && err != nil && err.Error() == "encryption key must have exactly 32 bytes" {
				t.Errorf("Unexpected error for valid encryption key: %v", err)
			}
		})
	}
}

func TestS3Storage_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	endpoint := os.Getenv("S3_ENDPOINT")
	bucket := os.Getenv("S3_BUCKET")
	accessKey := os.Getenv("S3_ACCESS_KEY")
	secretKey := os.Getenv("S3_SECRET_KEY")

	if endpoint == "" || bucket == "" || accessKey == "" || secretKey == "" {
		t.Skip("Skipping integration test: S3 environment variables not set")
	}

	opts := S3Opts{
		Endpoint:        endpoint,
		Bucket:          bucket,
		AccessKeyID:     accessKey,
		SecretAccessKey: secretKey,
		ObjPrefix:       "integration-test",
	}

	storage, err := NewS3Storage(opts)
	if err != nil {
		t.Fatalf("Failed to create S3Storage: %v", err)
	}

	ctx := context.Background()
	testKey := "integration/test.pem"
	testValue := []byte("integration test data")

	defer storage.Delete(ctx, testKey)

	err = storage.Store(ctx, testKey, testValue)
	if err != nil {
		t.Fatalf("Integration Store() failed: %v", err)
	}

	loadedValue, err := storage.Load(ctx, testKey)
	if err != nil {
		t.Fatalf("Integration Load() failed: %v", err)
	}

	if string(loadedValue) != string(testValue) {
		t.Errorf("Integration test: loaded value differs from stored value")
	}

	if !storage.Exists(ctx, testKey) {
		t.Errorf("Integration test: key should exist")
	}

	info, err := storage.Stat(ctx, testKey)
	if err != nil {
		t.Fatalf("Integration Stat() failed: %v", err)
	}

	if info.Key != testKey {
		t.Errorf("Integration test: Stat() returned wrong key")
	}

	err = storage.Delete(ctx, testKey)
	if err != nil {
		t.Fatalf("Integration Delete() failed: %v", err)
	}

	if storage.Exists(ctx, testKey) {
		t.Errorf("Integration test: key should not exist after deletion")
	}
}
