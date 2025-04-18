<?php

namespace src\controllers;

use Exception;
use src\core\{Request, Response};
use src\dao\UserRole;
use src\dto\DtoFactory;
use src\exceptions\{BadRequestHttpException, BaseHttpException, InternalServerErrorHttpException, HttpExceptionFactory};
use src\exceptions\UnauthorizedHttpException;
use src\services\AuthService;
use src\utils\{UserSession, Validator};
use src\utils\Csrf;

/**
 * Controller for handling authentication
 * Request & Response is not stored as property to make it stateless & singleton (inspired by NestJS default singleton lifecycle).
 */
class AuthController extends Controller
{
    // Dependency injection
    private AuthService $authService;

    public function __construct(AuthService $authService)
    {
        $this->authService = $authService;
    }

    /**
     * Renders the sign in page
     * Uses php form handling (handles GET & POST requests)
     */
    public function renderAndHandleSignIn(Request $req, Response $res): void
    {
        // Redirect if user is authenticated
        $this->redirectIfAuthenticated($req, $res);

        // Render the view
        $viewPathFromPages = 'auth/sign-in/index.php';

        // Data to pass to the view
        $title = 'LinkInPurry | Sign In';
        $description = 'Sign in to your LinkInPurry account';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/auth/sign-in.css" />
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags,
        ];

        if ($req->getMethod() == "GET") {
            // Get
            $res->renderPage($viewPathFromPages, $data);
        } else {
            // Post
            // Invalid CSRF token
            if (!Csrf::validateToken($req->getBody()['csrf_token'] ?? '')) {
                throw new UnauthorizedHttpException("Unauthorized");
            }
            
            // Validate the request body
            $rules = [
                'email' => ['required', 'email'],
                'password' => ['required']
            ];
            $validator = new Validator();
            $isValid = $validator->validate($req->getBody(), $rules);
            // Invalid request body
            if (!$isValid) {
                $data['errorFields'] = $validator->getErrorFields();
                $data['fields'] = $req->getBody();
                $res->renderPage($viewPathFromPages, $data);
            }

            // Authenticate the user
            try {
                $email = $req->getBody()['email'];
                $password = $req->getBody()['password'];
                $user = $this->authService->signIn($email, $password);
            } catch (BadRequestHttpException $e) {
                // Failed to authenticate
                $message = $e->getMessage();
                $data['errorFields'] = [
                    'email' => [$message],
                    'password' => [$message],
                ];
                $data['fields'] = $req->getBody();
                $res->renderPage($viewPathFromPages, $data);
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
                    'message' => "Internal server error",
                ];

                $res->renderError($dataError);
            }

            // Success
            // Set the user in the session
            UserSession::setUser($user);

            // If valid, redirect to the dashboard
            $this->redirectIfAuthenticated($req, $res);
        }
    }

    /**
     * Handles the sign out endpoint
     */
    public function handleSignOut(Request $req, Response $res): void
    {
        // Redirect if user is not authenticated
        if (!UserSession::isLoggedIn()) {
            $res->redirect('/');
        }

        // Sign out the user
        UserSession::destroy();

        // Redirect to the home page
        $responseData = DtoFactory::createSuccessDto('Sign out successful');
        $res->json(200, $responseData);
    }

    /**
     * Renders the sign up page
     */
    public function renderSignUp(Request $req, Response $res): void
    {
        // Redirect if user is authenticated
        $this->redirectIfAuthenticated($req, $res);

        // Render the view
        $viewPathFromPages = 'auth/sign-up/index.php';

        // Data to pass to the view (SSR)
        $title = 'LinkInPurry | Sign Up';
        $description = 'Sign up for a LinkInPurry account';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/auth/sign-up/sign-up.css" />
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags
        ];

        $res->renderPage($viewPathFromPages, $data);
    }

    /**
     * Render the sign up job seeker page
     */
    public function renderandhandleSignUpJobSeeker(Request $req, Response $res): void
    {
        // Redirect if user is authenticated
        $this->redirectIfAuthenticated($req, $res);

        // Render the view
        $viewPathFromPages = 'auth/sign-up/job-seeker/index.php';

        // Data to pass to the view (SSR)
        $title = 'LinkInPurry | Job Seeker Sign Up';
        $description = 'Sign up for a LinkInPurry account as a job seeker';
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/auth/sign-up/register.css" />
                <script src="/scripts/auth/sign-up/job-seeker.js" defer></script>
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags
        ];

        if ($req->getMethod() == "GET") {
            // Get
            $res->renderPage($viewPathFromPages, $data);
        } else {
            // Invalid CSRF token
            if (!Csrf::validateToken($req->getBody()['csrf_token'] ?? '')) {
                throw new UnauthorizedHttpException("Unauthorized");
            }
            // Post
            $name = $req->getBody()['name'];
            $email = $req->getBody()['email'];
            $password = $req->getBody()['password'];

            $rules = [
                'name' => ['required'],
                'email' => ['required', 'email'],
                'password' => ['required'],
            ];

            $validator = new Validator();
            $isValid = $validator->validate($req->getBody(), $rules);
            // Invalid request body
            if (!$isValid) {
                $data['errorFields'] = $validator->getErrorFields();
                $data['fields'] = $req->getBody();
                $res->renderPage($viewPathFromPages, $data);
            }

            // Authenticate the transaction
            try {
                $this->authService->createJobSeeker($name, $email, $password);
            } catch (BadRequestHttpException $e) {
                $data['errorFields'] = $this->handleDatabaseError($e->getMessage());
                $data['fields'] = $req->getBody();
                $res->renderPage($viewPathFromPages, $data);
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
                    'message' => "Internal server error",
                ];

                $res->renderError($dataError);
            }

            $res->redirect('/auth/sign-in');
        }
    }

    /**
     * Render the sign up company page
     */
    public function renderandhandleSignUpCompany(Request $req, Response $res): void
    {
        // Redirect if user is authenticated
        $this->redirectIfAuthenticated($req, $res);

        // Render the view
        $viewPathFromPages = 'auth/sign-up/company/index.php';

        // Data to pass to view (SSR)
        $title = "LinkInPurry | Company Sign Up";
        $description = "Sign up for a LinkInPurry account as a company";
        $additionalTags = <<<HTML
                <link rel="stylesheet" href="/styles/auth/sign-up/register.css" />
                <script src="/scripts/auth/sign-up/company.js" defer></script>
            HTML;
        $data = [
            'title' => $title,
            'description' => $description,
            'additionalTags' => $additionalTags
        ];

        if ($req->getMethod() == "GET") {
            // Get
            $res->renderPage($viewPathFromPages, $data);
        } else {
            // Post
            // Invalid CSRF token
            if (!Csrf::validateToken($req->getBody()['csrf_token'] ?? '')) {
                throw new UnauthorizedHttpException("Unauthorized");
            }
            $name = $req->getBody()['name'];
            $email = $req->getBody()['email'];
            $password = $req->getBody()['password'];
            $location = $req->getBody()['location'];
            $about = $req->getBody()['about'];

            $rules = [
                'name' => ['required'],
                'email' => ['required', 'email'],
                'password' => ['required'],
                'location' => ['required'],
                'about' => ['required']
            ];

            $validator = new Validator();
            $isValid = $validator->validate($req->getBody(), $rules);
            // Invalid request body
            if (!$isValid) {
                $data['errorFields'] = $validator->getErrorFields();
                $data['fields'] = $req->getBody();
                $res->renderPage($viewPathFromPages, $data);
            }


            // Authenticate the transaction
            try {
                $this->authService->createCompany($name, $email, $password, $location, $about);
            } catch (BadRequestHttpException $e) {
                $data['errorFields'] = $this->handleDatabaseError($e->getMessage());
                $data['fields'] = $req->getBody();
                $res->renderPage($viewPathFromPages, $data);
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
                    'message' => "Internal server error",
                ];

                $res->renderError($dataError);
            }
            $res->redirect('/auth/sign-in');
        }
    }

    /**
     * Handles the sign up for job seeker endpoint 
     */
    public function handleSignUpJobSeeker(Request $req, Response $res): void {}

    /**
     * Handle the sign up for company endpoint
     */
    public function handleSignUpCompany(Request $req, Response $res): void {}

    /**
     * Redirect user if already authenticated
     */
    public function redirectIfAuthenticated(Request $req, Response $res): void
    {
        if (UserSession::isLoggedIn()) {
            if (UserSession::getUserRole() === UserRole::JOBSEEKER) {
                // If job seeker
                $res->redirect('/jobs');
            } else {
                // If employer
                $res->redirect('/company/jobs');
            }
        }
    }

    private function handleDatabaseError(string $errormess): array
    {
        if (strpos($errormess, 'email') == true) {
            $data['errorFields'] = [
                'email' => ["Email already exist"]
            ];
            return $data['errorFields'];
        }

        $data['errorFields'] = [
            'name' => [$errormess],
            'email' => [$errormess],
            'password' => [$errormess],
        ];
        return $data['errorFields'];
    }
}
