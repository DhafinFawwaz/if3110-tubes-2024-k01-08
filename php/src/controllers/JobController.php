<?php

namespace src\controllers;

use DateTime;
use Exception;
use src\core\{Response, Request};
use src\dao\{LocationType, JobType, UserRole};
use src\dto\DtoFactory;
use src\exceptions\BadRequestHttpException;
use src\exceptions\BaseHttpException;
use src\exceptions\ConflictHttpException;
use src\exceptions\HttpExceptionFactory;
use src\exceptions\UnauthorizedHttpException;
use src\services\{JobService, UserService};
use src\utils\{UserSession, Utils, Validator, Csrf};
use src\views\components\PaginationComponent;

class JobController extends Controller
{
    private JobService $jobService;

    public function __construct(JobService $jobService)
    {
        $this->jobService = $jobService;
    }

    /**
     * Handle cv & video access request
     */
    public function handleAccessApplicationAttachment(Request $req, Response $res): void
    {
        $currentUserId = UserSession::getUserId();

        // Validate id path param
        $jobId = $req->getPathParams('jobId');
        $userId = $req->getPathParams('userId');
        if (!Utils::isInteger($jobId) || !Utils::isInteger($userId)) {
            $dataError = [
                'statusCode' => 404,
                'message' => "Page not found",
            ];
            $res->renderError($dataError);
        }

        $type = $req->getPathParams('type');
        // Validate tpye
        if ($type !== 'cv' && $type !== 'video') {
            $dataError = [
                'statusCode' => 404,
                'message' => "Page not found",
            ];
            $res->renderError($dataError);
        }

        // Validate request
        try {
            $application = $this->jobService->validateCvVideoRequest($currentUserId, $userId, $jobId);
        } catch (BaseHttpException $e) {
            $data = [
                'statusCode' => $e->getCode(),
                'message' => $e->getMessage(),
            ];

            $res->renderError($data);
        } catch (Exception $e) {
            $data = [
                'statusCode' => 500,
                'message' => "An error occurred while fetching job detail",
            ];
            $res->renderError($data);
        }

        // If no exception, redirect to the attachment
        $path = $type === 'cv' ? $application->getCvPath() : $application->getVideoPath();
        $res->blob($path);
    }

    /**
     * Render and handle the jobs list page for job-seeker
     * If user is authenticated and is company, redirect to company dashboard
     * I.S. user authenticated & authorized as JOBSEEKER (from middleware)
     * F.S. render the jobs list page
     * sorts (ony one at a time): sortCreatedAtAsc (default false)
     * filters: (no filter => all jobs)
     *  - job type (key=job-types, value=enum)
     *  - location type (key=location-types, value=enum)
     *  - daterange (key=created-at-from, value=date) & (key=created-at-to, value=timestamp)
     *  - search bar (position, location, job type) (key=search, value=string)
     *  - pagination (key=page, value=integer) (note: limit is fixed to 20)
     *  Invalid query parameters will be ignored (no error response)
     */
    public function renderJobs(Request $req, Response $res): void
    {
        $viewPathFromPages = 'jobs/index.php';

        // If user has session and is company, redirect to company dashboard
        if (UserSession::isLoggedIn() && UserSession::getUserRole() == UserRole::COMPANY) {
            $res->redirect('/company/dashboard');
        }

        // Base data to pass to the view
        $title = 'LinkInPurry | Jobs';
        $description = 'List of jobs available for you';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/jobs/job-list.css" />
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags
        ];

        // Get query parameters
        $rawJobTypes = $req->getQueryParams('job-types');
        $rawLocationTypes = $req->getQueryParams('location-types');
        $rawCreatedAtFrom = $req->getQueryParams('created-at-from');
        $rawCreatedAtTo = $req->getQueryParams('created-at-to');
        $rawSearch = $req->getQueryParams('search');
        $rawSortCreatedAt = $req->getQueryParams('sort-created-at');
        $rawPage = $req->getQueryParams('page');

        // Parse query parameters
        $queryParams = $this->parseJobQueryParams($rawJobTypes, $rawLocationTypes, $rawCreatedAtFrom, $rawCreatedAtTo, $rawSearch, $rawSortCreatedAt, $rawPage);
        $parsedJobTypes = $queryParams['job-types'];
        $parsedLocationTypes = $queryParams['location-types'];
        $parsedCreatedAtFrom = $queryParams['created-at-from'];
        $parsedCreatedAtTo = $queryParams['created-at-to'];
        $parsedSearch = $queryParams['search'];
        $parsedSortCreatedAt = $queryParams['is-created-at-asc'];
        $parsedPage = $queryParams['page'];

        try {
            // Get jobs data
            [$jobs, $meta] = $this->jobService->getJobs($parsedJobTypes, $parsedLocationTypes, $parsedCreatedAtFrom, $parsedCreatedAtTo, $parsedSearch, $parsedSortCreatedAt, $parsedPage);

            // Generate pagination component
            $paginationComponent = PaginationComponent::renderPagination($meta, $req->getUri());

            // Add data to pass to the view
            $data['jobs'] = $jobs;
            $data['meta'] = $meta;
            $data['filters'] = $queryParams;
            $data['paginationComponent'] = $paginationComponent;
        } catch (BaseHttpException $e) {
            // Render error page
            $dataError = [
                'statusCode' => $e->getCode(),
                'message' => $e->getMessage(),
            ];

            $res->renderError($dataError);
        } catch (Exception $e) {
            // Render Internal server error
            $dataError = [
                'statusCode' => 500,
                'message' => "An error occurred while fetching jobs",
            ];

            $res->renderError($dataError);
        }

        $res->renderPage($viewPathFromPages, $data);
    }

    /**
     * Render job detail page for job-seeker
     * 
     * Case 1: Unauthenticated user, in header render login button
     * Case 2: Authenticated user, company -> redirect to company dashboard
     * Case 3: Authenticated user, jobseeker:
     * Case 3a: Haven't applied -> render apply button
     * Case 3b: Already applied -> render path to CV & Video
     * Case 3c: Job closed -> render not found page
     */
    public function renderJobDetail(Request $req, Response $res): void
    {
        $viewPathFromPages = 'jobs/[jobId]/index.php';
        $currentUserId = UserSession::getUserId();

        $jobId = $req->getPathParams('jobId');
        // Validate job id
        if (!Utils::isInteger($jobId)) {
            $dataError = [
                'statusCode' => 404,
                'message' => "Page not found",
            ];
            $res->renderError($dataError);
        }

        // this is a public route, but should only be accessible by non auth or jobseeker
        // If user has session and is company, redirect to company dashboard
        if (UserSession::isLoggedIn() && UserSession::getUserRole() == UserRole::COMPANY) {
            $res->redirect('/company/dashboard');
        }

        // Base data to pass to the view
        $title = 'LinkInPurry | Job Detail';
        $description = 'Job detail';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/jobs/job-detail.css" />
                <link rel="stylesheet" href="/styles/carousel.css" />
                <script src="/scripts/carousel.js" defer></script>
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags
        ];

        try {
            // Get data needed
            [$job, $application] = $this->jobService->getJobDetail($currentUserId, $jobId);

            // Add data to pass to the view
            $data['job'] = $job;
            $data['application'] = $application;
        } catch (BaseHttpException $e) {
            // Render error page
            $dataError = [
                'statusCode' => $e->getCode(),
                'message' => $e->getMessage(),
            ];

            $res->renderError($dataError);
        } catch (Exception $e) {
            // Render Internal server error
            $dataError = [
                'statusCode' => 500,
                'message' => "An error occurred while fetching job detail",
            ];

            $res->renderError($dataError);
        }

        $res->renderPage($viewPathFromPages, $data);
    }

    /**
     * Render job application page for job-seeker
     * 
     * Contain job information,
     * Input CV file in pdf format,
     * Upload video (optional)
     */
    public function renderAndHandleApplyJob(Request $req, Response $res): void
    {
        $viewPathFromPages = 'jobs/[jobId]/apply/index.php';
        $currentUserId = UserSession::getUserId();

        // Validate path param
        $jobId = $req->getPathParams('jobId');
        if (!Utils::isInteger($jobId)) {
            $dataError = [
                'statusCode' => 404,
                'message' => "Page not found",
            ];
            $res->renderError($dataError);
        }

        // Base data to pass to the view
        $title = 'LinkInPurry | Apply Job';
        $description = 'Apply for a job';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/jobs/job-apply.css" />
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags
        ];

        try {
            // Get job data
            $job = $this->jobService->getJobDetail($currentUserId, $jobId)[0];
            $isAlreadyApplied = $this->jobService->isApplied($currentUserId, $jobId);

            // Add data to pass to the view
            $data['job'] = $job;
            $data['jobId'] = $jobId;

            if ($req->getMethod() == "GET") {
                if ($isAlreadyApplied) {
                    $res->redirect("/jobs/$jobId");
                } else {
                    // Render the page
                    $res->renderPage($viewPathFromPages, $data);
                }
            } else if ($req->getMethod() == "POST") {
                // Invalid CSRF token
                if (!Csrf::validateToken($req->getBody()['csrf_token'] ?? '')) {
                    throw new UnauthorizedHttpException("Unauthorized");
                }
                // Handle form submission

                // Validate request
                $rules = [
                    'cv' => ['requiredFile', 'file' => ['maxSize' => 5 * 1024 * 1024, 'allowedTypes' => ['application/pdf']]],
                    'video' => ['optional', 'file' => ['maxSize' => 50 * 1024 * 1024, 'allowedTypes' => ['video/mp4', 'video/x-msvideo', 'video/quicktime', 'video/x-matroska']]]
                ];

                $validator = new Validator();
                $isValid = $validator->validate($req->getBody(), $rules);

                if (!$isValid) {
                    $data['errorFields'] = $validator->getErrorFields();
                    $data['fields'] = $req->getBody();
                    $data['fields']['cv'] = $req->getBody()['cv'];
                    $res->renderPage($viewPathFromPages, $data);
                }

                // Upload CV and video
                $cv = $req->getBody()['cv'];
                $video = $req->getBody()['video'];

                try {
                    // Apply for job
                    $this->jobService->applyJob($currentUserId, $jobId, $cv, $video);
                }
                // Catch exceptions
                catch (ConflictHttpException $e) {
                    $res->redirect("/jobs/$jobId");
                } catch (BaseHttpException $e) {
                    // Render error view
                    $dataError = [
                        'statusCode' => $e->getCode(),
                        'message' => $e->getMessage(),
                    ];

                    $res->renderError($dataError);
                } catch (Exception $e) {
                    // TODO: Render Internal server error
                    $dataError = [
                        'statusCode' => 500,
                        'message' => "An error occurred while applying for the job",
                    ];

                    $res->renderError($dataError);
                }

                // Redirect to job detail page
                $res->redirect("/history");
            }
        } catch (BaseHttpException $e) {
            // Render error view
            $dataError = [
                'statusCode' => $e->getCode(),
                'message' => $e->getMessage(),
            ];
            $res->renderError($dataError);
        } catch (Exception $e) {
            // Render Internal server error
            $dataError = [
                'statusCode' => 500,
                'message' => "An error occurred while fetching job detail",
            ];
            $res->renderError($dataError);
        }
    }

    /**
     * Parse job page query params
     */
    private function parseJobQueryParams(
        ?array $rawJobTypes,
        ?array $rawLocationTypes,
        ?string $rawCreatedAtFrom,
        ?string $rawCreatedAtTo,
        ?string $rawSearch,
        ?string $rawSortCreatedAt,
        ?string $rawPage
    ): array {
        $isCreatedAtAsc = false; // Default sort
        $jobTypes = $locationTypes = $createdAtFrom = $createdAtTo = $search = $page = null;

        // Job types
        if ($rawJobTypes !== null) {
            foreach ($rawJobTypes as $jobTypeValue) {
                if (in_array($jobTypeValue, JobType::getValues())) {
                    if ($jobTypes === null) {
                        $jobTypes = [];
                    }
                    $jobTypes[] = JobType::fromString($jobTypeValue);
                }
            }
        }

        // Location types
        if ($rawLocationTypes !== null) {
            foreach ($rawLocationTypes as $locationTypeValue) {
                if (in_array($locationTypeValue, LocationType::getValues())) {
                    if ($locationTypes === null) {
                        $locationTypes = [];
                    }
                    $locationTypes[] = LocationType::fromString($locationTypeValue);
                }
            }
        }

        // Date formatiing:
        // yyyy-mm-dd => date
        // Created at from
        if ($rawCreatedAtFrom !== null) {
            $createdAtFromDateTime = DateTime::createFromFormat('Y-m-d', $rawCreatedAtFrom);
            if ($createdAtFromDateTime && $createdAtFromDateTime->format('Y-m-d') === $rawCreatedAtFrom) {
                $createdAtFrom = $createdAtFromDateTime;
            }
        }

        // Created at to
        if ($rawCreatedAtTo !== null) {
            $createdAtToDateTime = DateTime::createFromFormat('Y-m-d', $rawCreatedAtTo);
            if ($createdAtToDateTime && $createdAtToDateTime->format('Y-m-d') === $rawCreatedAtTo) {
                $createdAtTo = $createdAtToDateTime;
            }
        }

        // Search
        if ($rawSearch !== null && strlen($rawSearch) > 0) {
            $search = $rawSearch;
        }

        // Created at sort
        if ($rawSortCreatedAt !== null && $rawSortCreatedAt === "oldest-first") {
            $isCreatedAtAsc = true;
        }

        // Page number (default to 1)
        $page = 1;
        if ($rawPage !== null) {
            // Parse to integer
            $pageResult = filter_var($rawPage, FILTER_VALIDATE_INT);
            if ($pageResult == false || $pageResult < 1) {
                $page = 1;
            } else {
                $page = $pageResult;
            }
        }

        return [
            'job-types' => $jobTypes,
            'location-types' => $locationTypes,
            'created-at-from' => $createdAtFrom,
            'created-at-to' => $createdAtTo,
            'search' => $search,
            'is-created-at-asc' => $isCreatedAtAsc,
            'page' => $page
        ];
    }

    public function renderApplicationsHistory(Request $req, Response $res): void
    {
        $viewPathFromPages = 'history/index.php';
        $currentUserId = UserSession::getUserId();

        // Data to pass to the view (SSR)
        $title = 'LinkInPurry | History';
        $description = 'Your job applications history';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/jobs/history.css" />
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags
        ];

        // Get query parameters
        $rawPage = $req->getQueryParams('page');

        // Parse query parameters
        $queryParams = $this->parseHistoryQueryParams($rawPage);
        $parsedPage = $queryParams['page'];

        try {
            // Call service to get applications history
            [$applications, $meta] = $this->jobService->getApplicationsHistory($currentUserId, $parsedPage);

            // Generate pagination component
            $paginationComponent = PaginationComponent::renderPagination($meta, $req->getUri());

            // Add data to pass to the view
            $data['applications'] = $applications;
            $data['meta'] = $meta;
            $data['paginationComponent'] = $paginationComponent;
        } catch (BaseHttpException $e) {
            // Render error page
            $dataError = [
                'statusCode' => $e->getCode(),
                'message' => $e->getMessage(),
            ];

            $res->renderError($dataError);
        } catch (Exception $e) {
            // Render Internal server error
            $dataError = [
                'statusCode' => 500,
                'message' => "An error occurred while fetching your job applications history",
            ];

            $res->renderError($dataError);
        }

        // Render the page
        $res->renderPage($viewPathFromPages, $data);
    }

    private function parseHistoryQueryParams(?string $rawPage)
    {
        $page = 1;
        if ($rawPage !== null) {
            // Parse to integer
            $pageResult = filter_var($rawPage, FILTER_VALIDATE_INT);
            if ($pageResult == false || $pageResult < 1) {
                $page = 1;
            } else {
                $page = $pageResult;
            }
        }

        return [
            'page' => $page
        ];
    }

    public function renderJobSuggestion(Request $req, Response $res): void
    {
        // Render the view
        $viewPathFromPages = 'suggestion/index.php';

        // Data to pass to the view
        $title = 'LinkInPurry | Job Suggestion';
        $description = 'Get Your Jobs Suggestion';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/jobs/suggestion.css" />
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags,
        ];

        try {
            // Get jobs data
            $jobs = $this->jobService->getJobsSuggestion();


            // Add data to pass to the view
            $data['jobs'] = $jobs;
        } catch (Exception $e) {
            // TODO: Render Internal server error
            $dataError = [
                'statusCode' => $e->getCode(),
                'message' => $e->getMessage(),
            ];

            $res->renderError($dataError);
        }

        $res->renderPage($viewPathFromPages, $data);
    }
}
