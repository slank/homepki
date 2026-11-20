package storage

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func CreateBackupArchive(outputPath string, filePaths []string) error {
	if strings.TrimSpace(outputPath) == "" {
		return fmt.Errorf("output path is required")
	}
	if len(filePaths) == 0 {
		return fmt.Errorf("at least one file path is required")
	}

	outFile, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("create backup archive: %w", err)
	}
	defer outFile.Close()
	if err := outFile.Chmod(0o600); err != nil {
		return fmt.Errorf("restrict backup archive permissions: %w", err)
	}

	gzipWriter := gzip.NewWriter(outFile)
	defer gzipWriter.Close()

	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	for _, filePath := range filePaths {
		rootInfo, err := os.Stat(filePath)
		if err != nil {
			return fmt.Errorf("stat backup path %q: %w", filePath, err)
		}

		rootName := filepath.Base(filePath)
		err = filepath.Walk(filePath, func(currentPath string, info os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}

			relativePath, err := filepath.Rel(filePath, currentPath)
			if err != nil {
				return err
			}
			archivePath := rootName
			if relativePath != "." {
				archivePath = filepath.Join(rootName, relativePath)
			}

			header, err := tar.FileInfoHeader(info, "")
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(archivePath)
			if err := tarWriter.WriteHeader(header); err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}

			file, err := os.Open(currentPath)
			if err != nil {
				return err
			}
			_, copyErr := io.Copy(tarWriter, file)
			closeErr := file.Close()
			if copyErr != nil {
				return copyErr
			}
			return closeErr
		})
		if err != nil {
			return fmt.Errorf("archive backup path %q (%s): %w", filePath, rootInfo.Name(), err)
		}
	}

	return nil
}

func RestoreBackupArchive(archivePath string, outputDir string) error {
	if strings.TrimSpace(archivePath) == "" {
		return fmt.Errorf("archive path is required")
	}
	if strings.TrimSpace(outputDir) == "" {
		return fmt.Errorf("output directory is required")
	}

	inFile, err := os.Open(archivePath)
	if err != nil {
		return fmt.Errorf("open backup archive: %w", err)
	}
	defer inFile.Close()

	gzipReader, err := gzip.NewReader(inFile)
	if err != nil {
		return fmt.Errorf("create gzip reader: %w", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar entry: %w", err)
		}
		cleanName := filepath.Clean(header.Name)
		if cleanName == "." || cleanName == ".." || strings.HasPrefix(cleanName, ".."+string(filepath.Separator)) || filepath.IsAbs(cleanName) {
			return fmt.Errorf("unsafe path in backup archive: %q", header.Name)
		}

		targetPath := filepath.Join(outputDir, cleanName)
		if header.FileInfo().IsDir() {
			if err := os.MkdirAll(targetPath, header.FileInfo().Mode()); err != nil {
				return fmt.Errorf("create restore directory %q: %w", targetPath, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(targetPath), 0o700); err != nil {
			return fmt.Errorf("create restore parent for %q: %w", targetPath, err)
		}
		mode := header.FileInfo().Mode().Perm()
		if mode == 0 {
			mode = 0o600
		}
		outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return fmt.Errorf("create restore file %q: %w", targetPath, err)
		}
		if err := outFile.Chmod(mode); err != nil {
			outFile.Close()
			return fmt.Errorf("restore permissions for %q: %w", targetPath, err)
		}

		if _, err := io.Copy(outFile, tarReader); err != nil {
			outFile.Close()
			return fmt.Errorf("write restore file %q: %w", targetPath, err)
		}
		outFile.Close()
	}

	return nil
}

func FactoryResetSQLite(sqlitePath string) error {
	if strings.TrimSpace(sqlitePath) == "" {
		return fmt.Errorf("sqlite path is required")
	}
	for _, path := range []string{sqlitePath, sqlitePath + "-wal", sqlitePath + "-shm"} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove sqlite file %q: %w", path, err)
		}
	}
	return nil
}

func FactoryResetPath(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("protected path is required")
	}
	if err := os.RemoveAll(path); err != nil {
		return fmt.Errorf("remove protected path: %w", err)
	}
	return nil
}
