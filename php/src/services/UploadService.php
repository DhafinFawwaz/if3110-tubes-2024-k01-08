<?php

namespace src\services;

use src\utils\PathResolver;

/**
 * Service class for uploading files
 */
class UploadService
{

    private function limitFileName(string $fileName, int $maxLength): string
    {
        if (strlen($fileName) > $maxLength) {
            $fileName = substr($fileName, 0, $maxLength);
        }
        return $fileName;
    }
    /**
     * Uploads a file to a certain target directory
     * @param directoryFromPublic: target directory to upload the file
     * @param file: file array 
     * @return string: the file directory from the public directory
     * I.S. file is already validated at the start of controller
     * F.S. file is uploaded to the target directory
     */
    public function uploadOneFile(string $directoryFromPublic, array $normalizedFile): string
    {
        $originalFileName = $normalizedFile['name'];
        // Remove illegal characters from the
        // change non-alphanumeric characters (except . - _ ) to underscore 
        $validatedOriginalFileName = preg_replace('/[^a-zA-Z0-9.-_]/', '_', $originalFileName);

        // Max file name length is VARCHAR(255), the prefixes will be around 50 characters, so limit to 100 should be enough.
        $validatedOriginalFileName = $this->limitFileName($validatedOriginalFileName, 100);
        $finalFilename = uniqid() . '_' . $validatedOriginalFileName;

        $folderDirectoryToMove = PathResolver::resolve(__DIR__ . '/../../public/' . $directoryFromPublic);
        $fileDirectoryToMove = PathResolver::resolve($folderDirectoryToMove . '/' . $finalFilename);
        $fileDirectoryFromPublic = PathResolver::resolve($directoryFromPublic . '/' . $finalFilename);
        // Create the target directory if it doesn't exist

        if (!file_exists($folderDirectoryToMove)) {
            if (!mkdir($folderDirectoryToMove, 0775, true)) {
                throw new \Exception('Failed to create directory: ' . $folderDirectoryToMove);
            }
        }

        $x = move_uploaded_file($normalizedFile['tmp_name'], $fileDirectoryToMove);
        // echo var_dump($x);
        // Move the file to the target directory
        if (!$x) {
            throw new \Exception('Failed to upload file');
        }

        return $fileDirectoryFromPublic;
    }

    /**
     * Uploads multiple files to a certain target directory
     * @param directoryFromPublic: target directory to upload the file
     * @param rawFiles: raw files array
     */
    public function uploadMultipleFiles(string $directoryFromPublic, array $rawFiles): array
    {
        $uploadedFiles = [];
        for ($i = 0; $i < count($rawFiles['name']); $i++) {
            $normalizedFile = [
                'name' => $rawFiles['name'][$i],
                'type' => $rawFiles['type'][$i],
                'tmp_name' => $rawFiles['tmp_name'][$i],
                'error' => $rawFiles['error'][$i],
                'size' => $rawFiles['size'][$i],
            ];

            $uploadedFiles[] = self::uploadOneFile($directoryFromPublic, $normalizedFile);
        }

        return $uploadedFiles;
    }

    /**
     * Deletes a file from the public directory
     * @param fileDirectoryFromPublic: file directory from the public directory
     */
    public function deleteOneFile(string $fileDirectoryFromPublic)
    {
        $fileDirectoryToDelete = PathResolver::resolve(__DIR__ . '/../../public/' . $fileDirectoryFromPublic);

        if (!file_exists($fileDirectoryToDelete)) {
            throw new \Exception('File not found');
        }

        if (!unlink($fileDirectoryToDelete)) {
            throw new \Exception('Failed to delete file');
        }
    }

    /**
     * Deletes multiple files from the public directory
     * @param fileDirectoriesFromPublic: file directories from the public directory
     */
    public function deleteMultipleFiles(array $fileDirectoriesFromPublic)
    {
        foreach ($fileDirectoriesFromPublic as $fileDirectoryFromPublic) {
            self::deleteOneFile($fileDirectoryFromPublic);
        }
    }
}
