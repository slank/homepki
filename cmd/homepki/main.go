package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"homepki/internal/config"
	"homepki/internal/pki"
	"homepki/internal/storage"
	"homepki/internal/web"
	"homepki/internal/yubikey"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

func main() {
	configPath := flag.String("config", "configs/dev.yaml", "Path to config file")
	migrate := flag.Bool("migrate", false, "Apply pending migrations and exit")
	rollbackSteps := flag.Int("rollback", 0, "Rollback the latest N migrations and exit")
	checkYubiKey := flag.Bool("check-yubikey", false, "Check connected YubiKey PIV readiness and exit")
	checkYubiKeySigning := flag.Bool("check-yubikey-signing", false, "Sign and verify a challenge with the YubiKey, then exit")
	ykmanBinary := flag.String("ykman-binary", "ykman", "Path to ykman for -check-yubikey")
	stepBinaryFlag := flag.String("step-binary", "step", "Path to step for -check-yubikey-signing")
	yubiKeyPINFile := flag.String("yubikey-pin-file", "", "PIN file for -check-yubikey-signing")
	yubiKeySlot := flag.String("yubikey-signing-slot", "83", "PIV slot for -check-yubikey-signing")
	flag.Parse()

	_, _, _ = version, commit, buildDate

	if *checkYubiKey {
		runYubiKeyCheck(*ykmanBinary)
		return
	}
	if *checkYubiKeySigning {
		runYubiKeySigningCheck(*stepBinaryFlag, *yubiKeyPINFile, *yubiKeySlot)
		return
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		exitErr(fmt.Errorf("load config: %w", err))
	}
	if err := cfg.Validate(); err != nil {
		exitErr(fmt.Errorf("validate config: %w", err))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := storage.OpenSQLite(ctx, storage.SQLiteOptions{
		Path: cfg.Storage.SQLitePath,
	})
	if err != nil {
		exitErr(fmt.Errorf("open sqlite: %w", err))
	}
	defer db.Close()

	if *migrate {
		if err := storage.ApplyMigrationsFromDir(ctx, db, "migrations"); err != nil {
			exitErr(fmt.Errorf("apply migrations: %w", err))
		}
		fmt.Println("migrations applied")
	}

	if *rollbackSteps > 0 {
		if err := storage.RollbackMigrationsFromDir(ctx, db, "migrations", *rollbackSteps); err != nil {
			exitErr(fmt.Errorf("rollback migrations: %w", err))
		}
		fmt.Println("migrations rolled back")
	}

	if *migrate || *rollbackSteps > 0 {
		return
	}

	if err := storage.ApplyMigrationsFromDir(ctx, db, "migrations"); err != nil {
		exitErr(fmt.Errorf("apply startup migrations: %w", err))
	}

	var pkiService pki.Service
	switch cfg.PKI.Provider {
	case "step":
		pkiService = pki.StepCAService{Config: pki.StepCAConfig{
			StepBinary:              cfg.PKI.StepBinary,
			CAURL:                   cfg.PKI.CAURL,
			RootCertificatePath:     cfg.PKI.RootCertificatePath,
			Provisioner:             cfg.PKI.Provisioner,
			ProvisionerPasswordFile: cfg.PKI.ProvisionerPasswordFile,
			StepPath:                cfg.PKI.StepPath,
			CAName:                  cfg.PKI.CAName,
			CADNSName:               cfg.PKI.CADNSName,
			CAAddress:               cfg.PKI.CAAddress,
			AdditionalProvisionArgs: cfg.PKI.AdditionalProvisionArgs,
			StepCABinary:            cfg.PKI.StepCABinary,
			SystemctlBinary:         cfg.PKI.SystemctlBinary,
			SystemctlArgs:           cfg.PKI.SystemctlArgs,
			CAServiceName:           cfg.PKI.CAServiceName,
			UseYubiKey:              cfg.Security.RequireYubiKey,
			YubiKeyPINFile:          cfg.PKI.YubiKeyPINFile,
			YubiKeyRootSlot:         cfg.PKI.YubiKeyRootSlot,
			YubiKeyIntermediateSlot: cfg.PKI.YubiKeyIntermediateSlot,
			YKManBinary:             cfg.YubiKey.YKManBinary,
		}}
	default:
		pkiService = pki.MockService{}
	}

	yubiKeyClient := yubikey.CommandClient{Config: yubikey.CommandClientConfig{
		YKManBinary: cYubiKeyBinary(cfg.YubiKey.YKManBinary),
		PKCS11Tool:  cfg.YubiKey.PKCS11ToolPath,
		LibraryPath: cfg.YubiKey.LibraryPath,
		SigningSlot: cfg.YubiKey.SigningSlot,
		StepBinary:  cfg.PKI.StepBinary,
	}}

	protectedPaths := make([]string, 0, 1)
	if cfg.PKI.StepPath != "" {
		protectedPaths = append(protectedPaths, cfg.PKI.StepPath)
	}
	if cfg.PKI.YubiKeyPINFile != "" {
		protectedPaths = append(protectedPaths, cfg.PKI.YubiKeyPINFile)
	}

	server := web.NewServer(web.Server{
		DB:                   db,
		PKI:                  pkiService,
		YubiKey:              yubiKeyClient,
		RequireYubiKey:       cfg.Security.RequireYubiKey,
		SessionTTL:           12 * time.Hour,
		AllowInsecureCookies: cfg.Security.AllowInsecureLocalSessionCookie,
		SQLitePath:           cfg.Storage.SQLitePath,
		ConfigPath:           *configPath,
		BackupOutputDir:      ".",
		ProtectedPaths:       protectedPaths,
		SystemctlBinary:      cfg.PKI.SystemctlBinary,
		SystemctlArgs:        cfg.PKI.SystemctlArgs,
		AppServiceName:       "homepki.service",
		CAServiceName:        cfg.PKI.CAServiceName,
	})

	address := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	log.Printf("homepki listening on %s", address)
	if err := http.ListenAndServe(address, server); err != nil {
		exitErr(fmt.Errorf("start server: %w", err))
	}
}

func cYubiKeyBinary(value string) string {
	if value == "" {
		return "ykman"
	}
	return value
}

func runYubiKeyCheck(ykmanBinary string) {
	client := yubikey.CommandClient{Config: yubikey.CommandClientConfig{
		YKManBinary: ykmanBinary,
	}}
	devices, err := client.Discover(context.Background())
	if err != nil {
		exitErr(fmt.Errorf("check yubikey: %w", err))
	}

	ready := false
	for _, device := range devices {
		pivStatus := "unavailable"
		if device.HasPIV {
			pivStatus = "enabled"
			ready = true
		}
		fmt.Printf(
			"model=%q serial=%q firmware=%q piv=%s\n",
			device.Model,
			device.Serial,
			device.Firmware,
			pivStatus,
		)
	}
	if !ready {
		exitErr(fmt.Errorf("no connected YubiKey exposes PIV/CCID"))
	}
}

func runYubiKeySigningCheck(stepBinary, pinFile, slot string) {
	if pinFile == "" {
		exitErr(errors.New("yubikey pin file is required"))
	}
	pinBytes, err := os.ReadFile(pinFile)
	if err != nil {
		exitErr(fmt.Errorf("read yubikey pin file: %w", err))
	}
	pin := strings.TrimSpace(string(pinBytes))
	if pin == "" {
		exitErr(errors.New("yubikey pin file is empty"))
	}

	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		exitErr(fmt.Errorf("generate signing challenge: %w", err))
	}
	digest := sha256.Sum256(challenge)

	client := yubikey.CommandClient{Config: yubikey.CommandClientConfig{
		StepBinary:  stepBinary,
		SigningSlot: slot,
	}}
	result, err := client.Sign(context.Background(), yubikey.SignRequest{
		Algorithm:    "RSA-PKCS",
		Digest:       digest[:],
		PIN:          pin,
		RequireTouch: true,
	})
	if err != nil {
		exitErr(fmt.Errorf("verify yubikey signing: %w", err))
	}
	if len(result.Signature) == 0 {
		exitErr(errors.New("verify yubikey signing: empty signature"))
	}
	fmt.Printf("YubiKey signing verification passed for slot %s (%d signature bytes).\n", slot, len(result.Signature))
}

func exitErr(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
