<?php
use src\utils\Csrf;
$csrfToken = Csrf::generateToken();
use src\dao\JobType;
use src\dao\LocationType;

?>

<main class="main">
    <!-- Card -->
    <section class="card">
        <div>
            <!-- Back button -->
            <a href="/jobs/<?= htmlspecialchars($job->getJobId(), ENT_QUOTES, 'utf-8') ?>" class="card__back">
                <svg class="back__icon" xmlns="hsttp://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24"
                    fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                    class="lucide lucide-arrow-left">
                    <path d="m12 19-7-7 7-7" />
                    <path d="M19 12H5" />
                </svg>

                <span>Back</span>
            </a>

            <div class="header__group">
                <!-- Title -->
                <h1 class="header__title">
                    <?= htmlspecialchars($job->getPosition()) ?>
                </h1>

                <!-- Tags -->
                <div class="header__tags">
                    <!-- Job type -->
                    <div class="badge badge--default">
                        <?= htmlspecialchars(JobType::renderText($job->getJobType())) ?>
                    </div>

                    <!-- Location Type -->
                    <div class="badge badge--secondary ">
                        <?= htmlspecialchars(LocationType::renderText($job->getLocationType())) ?>
                    </div>

                </div>

                <div class="header__informations">
                    <!-- Company -->
                    <div class="header__information">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                            class="lucide lucide-building-2 icon--sm--margin">
                            <path d="M6 22V4a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v18Z" />
                            <path d="M6 12H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h2" />
                            <path d="M18 9h2a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2h-2" />
                            <path d="M10 6h4" />
                            <path d="M10 10h4" />
                            <path d="M10 14h4" />
                            <path d="M10 18h4" />
                        </svg>

                        <span>
                            <?= htmlspecialchars($job->getCompanyDetail()->getName()) ?>
                        </span>
                    </div>

                    <!-- Location -->
                    <div class="header__information">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-map-pin icon--sm--margin">
                            <path d="M20 10c0 4.993-5.539 10.193-7.399 11.799a1 1 0 0 1-1.202 0C9.539 20.193 4 14.993 4 10a8 8 0 0 1 16 0" />
                            <circle cx="12" cy="10" r="3" />
                        </svg>

                        <span>
                            <?= htmlspecialchars($job->getCompanyDetail()->getLocation()) ?>
                        </span>
                    </div>

                    <!-- Created at -->
                    <div class="header__information">
                        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none"
                            stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"
                            class="lucide lucide-calendar-days icon--sm--margin">
                            <path d="M8 2v4" />
                            <path d="M16 2v4" />
                            <rect width="18" height="18" x="3" y="4" rx="2" />
                            <path d="M3 10h18" />
                            <path d="M8 14h.01" />
                            <path d="M12 14h.01" />
                            <path d="M16 14h.01" />
                            <path d="M8 18h.01" />
                            <path d="M12 18h.01" />
                            <path d="M16 18h.01" />
                        </svg>

                        <span>
                            <?= htmlspecialchars($job->getCreatedAt()->format('m/d/Y')) ?>
                        </span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Form -->
        <form
            id="create-job-form"
            class="form"
            action="/jobs/<?= htmlspecialchars($jobId, ENT_QUOTES, 'UTF-8') ?>/apply"
            method="POST"
            enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <!-- Title -->
            <h1 class="card__title">
                Apply For This Job
            </h1>

            <!-- Upload -->
            <div class="form__group">
                <!-- Upload CV -->
                <label for="cv" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['cv'])): ?>
                        <?= htmlspecialchars($errorFields['cv'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Upload Your CV
                </label>

                <input class="input" name="cv" type="file" accept=".pdf" />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['cv'])): ?>
                        <?= htmlspecialchars($errorFields['cv'][0] ?? '') ?>
                    <?php endif; ?>
                </p>

            </div>

            <div class="form__group">
                <!-- Upload Video -->
                <label for="video" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['video'])): ?>
                        <?= htmlspecialchars($errorFields['video'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Upload Video (Optional)
                </label>

                <input class="input" name="video" type="file" accept="video/*" multiple />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['video'])): ?>
                        <?= htmlspecialchars($errorFields['video'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>


            <!-- Submit -->
            <button type="submit" class="button button--default-size button--default-color">
                Apply Now
            </button>
        </form>
    </section>
</main>