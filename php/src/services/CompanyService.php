<?php

namespace src\services;

use DateTime;
use Exception;
use src\dao\{ApplicationDao, ApplicationStatus, LocationType, JobType, JobDao, CompanyDetailDao};
use src\exceptions\HttpExceptionFactory;
use src\repositories\{ApplicationRepository, JobRepository, UserRepository};
use src\utils\PathResolver;

class CompanyService extends Service
{
    // Dependency injection
    private UserRepository $userRepository;
    private JobRepository $jobRepository;
    private ApplicationRepository $applicationRepository;
    private UploadService $uploadService;


    public function __construct(UserRepository $userRepository, JobRepository $jobRepository, ApplicationRepository $applicationRepository, UploadService $uploadService)
    {
        $this->userRepository = $userRepository;
        $this->jobRepository = $jobRepository;
        $this->applicationRepository = $applicationRepository;
        $this->uploadService = $uploadService;
    }

    /**
     * Get company profile
     * @param int $userId - The user id
     * @throws HttpException
     * @return CompanyDetailDao - The company profile
     */
    public function getCompanyProfile(int $userId): CompanyDetailDao
    {
        // Find company detail by user id
        try {
            $companyDetail = $this->userRepository->findCompanyDetailByUserId($userId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching company profile");
        }

        if ($companyDetail == null) {
            throw HttpExceptionFactory::createNotFound("Company profile not found");
        }

        return $companyDetail;
    }

    /**
     * Get current company's job applications with CSV
     * Returns the csv values:
     * the first row must be the header
     * the next is the values in the CSVs
     */
    public function getCompanyJobApplicationCSVData(int $companyId, int $jobId)
    {
        // Validate if company is authorized to view applications
        try {
            $job = $this->jobRepository->getJobById($jobId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("Failed to get job");
        }

        // If job not found
        if ($job == null) {
            throw HttpExceptionFactory::createNotFound("Job posting not found");
        }

        // Check if authorized
        if ($job->getCompanyId() != $companyId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to view this job's applications");
        }

        $result = [];
        $result[] = [
            'id_application',
            'id_job',
            'job_position',
            'id_user',
            'user_name',
            'user_email',
            'apply_date',
            'cv_url',
            'video_url',
            'status',
        ];

        // Get applications of the job id
        try {
            $applications = $this->applicationRepository->getAllJobApplicationsUnpaginated($companyId, $jobId);
        } catch (Exception $e) {
            // echo $e->getMessage();
            throw HttpExceptionFactory::createInternalServerError("Failed to get job applications");
        }

        $baseURL = PathResolver::getBaseUrl();

        foreach ($applications as $application) {
            $cvURL = $baseURL . $application->getCVPath();
            $videoURL = $application->getVideoPath() ? $baseURL . $application->getVideoPath() : 'N/A';

            $result[] = [
                $application->getApplicationId(),
                $application->getJob()->getJobId(),
                $application->getJob()->getPosition(),
                $application->getUser()->getId(),
                $application->getUser()->getName(),
                $application->getUser()->getEmail(),
                $application->getCreatedAt()->format('Y-m-d H:i:s'),
                $cvURL,
                $videoURL,
                $application->getStatus()->value,
            ];
        }

        return $result;
    }

    /**
     * Update company profile
     * @param int $userId - The user id
     * @param string $name - The company name
     * @param string $location - The company location
     * @param string $about - The company about
     * @throws HttpException
     * @return void
     */
    public function updateCompanyProfile(int $userId, string $name, string $location, string $about): void
    {
        // Validate company
        try {
            $companyDetail = $this->userRepository->findCompanyDetailByUserId($userId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching company profile");
        }

        // If company not found
        if ($companyDetail == null) {
            throw HttpExceptionFactory::createNotFound("Company profile not found");
        }

        // Check if authorized
        if ($companyDetail->getUserId() != $userId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to update this company profile");
        }

        try {
            // Update company profile
            $companyDetail->setName($name);
            $companyDetail->setLocation($location);
            $companyDetail->setAbout($about);
            $this->userRepository->updateCompanyDetail($companyDetail);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while updating company profile");
        }
    }

    /**
     * Create a new job posting for current logged in company
     * @param string $userId - The user id (validated through middleware)
     * @param string $position - The job position
     * @param string $description - The job description
     * @param JobType $jobType - The job type
     * @param LocationType $locationType - The location type
     * @param array $rawAttachments - Array of raw attachments
     * @throws HttpException
     * @return [job, attachments] - The new job and attachments
     */
    public function createJob(int $userId, string $position, string $description, JobType $jobType, LocationType $locationType, array $rawAttachments): array
    {
        $isAttachmentEmpty = $rawAttachments['error'][0] == 4;

        if ($isAttachmentEmpty) {
            // Create a job without attachments
            try {
                $job = $this->jobRepository->createJob($userId, $position, $description, $jobType, $locationType);
            } catch (Exception $e) {
                throw HttpExceptionFactory::createInternalServerError("An error occurred while creating job posting");
            }

            return [$job, []];
        } else {
            // Upload files to server
            try {
                $directoryFromPublic = '/uploads/job-attachments/';
                $uploadedFilePaths = $this->uploadService->uploadMultipleFiles($directoryFromPublic, $rawAttachments);
            } catch (Exception $e) {
                throw HttpExceptionFactory::createInternalServerError("An error occurred while uploading job attachments");
            }

            // Create job and its attachments
            try {
                [$job, $jobAttachments] = $this->jobRepository->createJobAndAttachments($userId, $position, $description, $jobType, $locationType, $uploadedFilePaths);
            } catch (Exception $e) {
                // Handle case when file already uploaded but sql row is already inserted. Storage Exhaustion vuln.
                $this->uploadService->deleteMultipleFiles($uploadedFilePaths);
                throw HttpExceptionFactory::createInternalServerError("An error occurred while creating job posting");
            }

            return [$job, $jobAttachments];
        }
    }

    /**
     * Get job detail posting
     * @param string $jobId - The job id
     * @throws HttpException
     * @return JobDao - The job posting (with attachments)
     */
    public function getJobDetail(int $jobId): JobDao
    {
        // Get job by id
        try {
            $job = $this->jobRepository->getJobByIdWithAttachments($jobId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job posting");
        }

        // If job not found
        if ($job == null) {
            throw HttpExceptionFactory::createNotFound("Job posting not found");
        }

        return $job;
    }

    /**
     * Get many company's jobs with filter (job type, location type, is open)
     * Company id is validated through middleware
     */
    public function getCompanyJobs(int $companyId, ?array $isOpens, ?array $jobTypes, ?array $locationTypes, ?DateTime $createdAtFrom, ?DateTime $createdAtTo, ?string $search, bool $isCreatedAtAsc, ?int $page): array
    {
        // Set limit to only 10
        $limit = 10;

        // Get company's jobs with filter
        try {
            [$jobs, $meta] = $this->jobRepository->getCompanyJobsWithFilter($companyId, $isOpens, $jobTypes, $locationTypes, $createdAtFrom, $createdAtTo, $search, $isCreatedAtAsc, $page, $limit);
        } catch (Exception $e) {
            // echo $e->getMessage();
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching company's job postings");
        }

        return [$jobs, $meta];
    }

    /**
     * Get application detial
     */
    public function getCompanyJobApplication(int $currentUserId, int $applicationId): ApplicationDao
    {
        // Get application by id
        try {
            $application = $this->applicationRepository->getOneJobApplication($applicationId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job application");
        }

        // If application not found
        if ($application == null) {
            throw HttpExceptionFactory::createNotFound("Job application not found");
        }

        // Check if company is authorized to view application
        if ($application->getJob()->getCompanyId() != $currentUserId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to view this job application");
        }

        return $application;
    }


    /**
     * Get a company's job applications (paginated)
     * @param int job_id
     * @param int page
     */
    public function getCompanyJobApplications(int $companyId, int $job_id, int $page): array
    {
        // base limit
        $limit = 10;

        // Validate if company is authorized to view applications
        try {
            $job = $this->jobRepository->getJobById($job_id);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("Failed to get job");
        }

        // If job not found
        if ($job == null) {
            throw HttpExceptionFactory::createNotFound("Job posting not found");
        }

        // Check if authorized
        if ($job->getCompanyId() != $companyId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to view this job's applications");
        }

        // Get applications of the job id
        try {
            [$applications, $meta] = $this->applicationRepository->getJobApplications($job_id, $page, $limit);
        } catch (Exception $e) {
            // echo $e->getMessage();
            throw HttpExceptionFactory::createInternalServerError("Failed to get job applications");
        }

        return [$job, $applications, $meta];
    }



    /**
     * Edit a job posting for current logged in company
     * @param string $currentUserId - The user id
     * @param string $jobId - The job id
     * @param string $position - The job position
     * @param string $description - The job description
     * @param bool $isOpen - The job status
     * @param JobType $jobType - The job type
     * @param LocationType $locationType - The location type
     * @param array $attachments - Array of raw attachments
     * @throws HttpException
     * @return [job, attachments] - The edited job and attachments
     */
    public function editJob(int $currentUserId, int $jobId, string $position, string $description, bool $isOpen, JobType $jobType, LocationType $locationType, array $attachments): array
    {
        // Validate job
        try {
            $job = $this->jobRepository->getJobById($jobId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job posting");
        }

        // If job not found
        if ($job == null) {
            throw HttpExceptionFactory::createNotFound("Job posting not found");
        }

        // Check if authorized
        if ($job->getCompanyId() != $currentUserId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to edit this job posting");
        }

        $job->setPosition($position);
        $job->setDescription($description);
        $job->setIsOpen($isOpen);
        $job->setJobType($jobType);
        $job->setLocationType($locationType);

        $isAttachmentEmpty = $attachments['error'][0] == 4;
        if (!$isAttachmentEmpty) {
            // If new attachments are uploaded
            // Upload files to server
            try {
                $directoryFromPublic = '/uploads/job-attachments/';
                $uploadedFilePaths = $this->uploadService->uploadMultipleFiles($directoryFromPublic, $attachments);
            } catch (Exception $e) {
                throw HttpExceptionFactory::createInternalServerError("An error occurred while uploading job attachments");
            }

            // Edit job and its attachments
            try {
                $jobAttachments = $this->jobRepository->editJobAndCreateAttachments($job, $uploadedFilePaths);
            } catch (Exception $e) {
                // Handle case when file already uploaded but sql row is already inserted. Storage Exhaustion vuln.
                $this->uploadService->deleteMultipleFiles($uploadedFilePaths);
                throw HttpExceptionFactory::createInternalServerError("An error occurred while editing job posting");
            }

            return [$job, $jobAttachments];
        } else {
            // If no new attachments are uploaded
            // Edit job
            try {
                $this->jobRepository->editJob($job);
            } catch (Exception $e) {
                throw HttpExceptionFactory::createInternalServerError("An error occurred while editing job posting");
            }

            return [$job, []];
        }
    }

    /**
     * Update a job application status
     * @param string $currentUserId - The user id
     * @param string $applicationId - The application id
     * @param ApplicationStatus $status - The application status
     * @param string $message - The application message
     */
    public function updateJobApplicationStatus(int $currentUserId, int $applicationId, ApplicationStatus $status, string $message): void
    {
        // Validate application
        try {
            $application = $this->applicationRepository->getOneJobApplication($applicationId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job application");
        }

        // If application not found
        if ($application == null) {
            throw HttpExceptionFactory::createNotFound("Job application not found");
        }

        // Validate if user is authorized to update application status
        if ($application->getJob()->getCompanyId() != $currentUserId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to update this job application status");
        }

        // Validate initial status
        if ($application->getStatus() != ApplicationStatus::WAITING) {
            throw HttpExceptionFactory::createBadRequest("Application status is not pending");
        }

        // Update application status
        $application->setStatus($status);
        $application->setStatusReason($message);
        try {
            $this->applicationRepository->updateApplicationStatus($application);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while updating job application status");
        }
    }

    /**
     * Delete a job posting for current logged in company
     * Deletes the job and its attachments (database & server). Sets the user's application to be null.
     * @param string $currentUserId - The user id
     * @param string $jobId - The job id
     */
    public function deleteJob(int $currentUserId, int $jobId): void
    {
        // Validate job
        try {
            $job = $this->jobRepository->getJobByIdWithAttachments($jobId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job posting");
        }

        // If job not found
        if ($job == null) {
            throw HttpExceptionFactory::createNotFound("Job posting not found");
        }

        // Check if authorized
        if ($job->getCompanyId() != $currentUserId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to delete this job posting");
        }

        // // Get all the applications
        // try {
        //     $applications = $this->applicationRepository->getAllJobApplicationsUnpaginated($currentUserId, $jobId);
        // } catch (Exception $e) {
        //     throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job applications");
        // }

        // Delete job
        try {
            $this->jobRepository->deleteJob($job);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while deleting job posting");
        }

        // Delete job attachment files from server
        // NOTE: DUMMY DATA DOESN'T ACTUALLY STORE FILE PATHS
        // try {
        //     // Delete all the cv path and the video path (if any)
        //     $applicationFiles = [];
        //     foreach ($applications as $application) {
        //         $cvPath = $application->getCVPath();
        //         $videoPath = $application->getVideoPath();

        //         if ($cvPath) {
        //             $applicationFiles[] = $cvPath;
        //         }

        //         if ($videoPath) {
        //             $applicationFiles[] = $videoPath;
        //         }
        //     }

        //     if (count($applicationFiles) > 0) {
        //         $this->uploadService->deleteMultipleFiles($applicationFiles);
        //     }
        // } catch (Exception $e) {
        //     throw HttpExceptionFactory::createInternalServerError("An error occurred while deleting job attachments");
        // }

        // Delete job attachment files from server
        // NOTE: DUMMY DATA DOESN'T ACTUALLY STORE FILE PATHS
        // try {
        //     $fileDirectories = array_map(fn($attachment) => $attachment->getFilePath(), $job->getAttachments());
        //     if (count($fileDirectories) > 0) {
        //         $this->uploadService->deleteMultipleFiles($fileDirectories);
        //     }
        // } catch (Exception $e) {
        //     throw HttpExceptionFactory::createInternalServerError("An error occurred while deleting job attachments");
        // }
    }


    /**
     * Delete a job attachment
     */
    public function deleteJobAttachment(int $currentUserId, int $jobAttachmentId): void
    {
        // Validate job attachment
        try {
            $jobAttachment = $this->jobRepository->getJobAttachmentById($jobAttachmentId);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job attachment");
        }

        // If job attachment not found
        if ($jobAttachment == null) {
            throw HttpExceptionFactory::createNotFound("Job attachment not found");
        }

        // Validate job
        try {
            $job = $this->jobRepository->getJobByIdWithAttachments($jobAttachment->getJobId());
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while fetching job posting");
        }

        // If job not found
        if ($job == null) {
            throw HttpExceptionFactory::createNotFound("Job posting not found");
        }

        // Check if authorized
        if ($job->getCompanyId() != $currentUserId) {
            throw HttpExceptionFactory::createForbidden("You are not authorized to delete this job attachment");
        }

        // Attachment is optional (QnA No. 30)
        // // If attachment is the only one
        // if (count($job->getAttachments()) == 1) {
        //     throw HttpExceptionFactory::createBadRequest("Job posting must have at least one attachment");
        // }

        // Delete job attachment
        try {
            $this->jobRepository->deleteJobAttachment($jobAttachment);
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while deleting job attachment");
        }

        // Delete file from server
        try {
            $this->uploadService->deleteOneFile($jobAttachment->getFilePath());
        } catch (Exception $e) {
            throw HttpExceptionFactory::createInternalServerError("An error occurred while deleting job attachment");
        }
    }
}
