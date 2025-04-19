<?php
use src\utils\Csrf;
$csrfToken = Csrf::generateToken();
use src\dao\ApplicationStatus;
use src\dao\JobType;
use src\dao\LocationType;
use src\utils\Sanitizer;

?>


<!-- For job lists -->
<main class="container">
    <!-- Application Information -->
    <article class="container__card">
        <!-- Title -->
        <header class="card__header">
            <!-- Back button -->
            <a href="/company/jobs/<?= htmlspecialchars($application->getJob()->getJobId(), ENT_QUOTES, 'utf-8'); ?>/applications" class="header__back">
                <svg class="back__icon" xmlns="hsttp://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-arrow-left">
                    <path d="m12 19-7-7 7-7" />
                    <path d="M19 12H5" />
                </svg>

                <span>Back</span>
            </a>

            <div class="header__group">
                <!-- Title -->
                <h1 class="header__title">
                    <?= htmlspecialchars($application->getJob()->getPosition()) ?>
                </h1>

                <!-- Tags (status) -->
                <div class="header__tags">
                    <!-- Job type -->
                    <?php if ($application->getStatus() == ApplicationStatus::ACCEPTED): ?>
                        <div class="badge badge--green">
                            Accepted
                        </div>
                    <?php elseif ($application->getStatus() == ApplicationStatus::REJECTED): ?>
                        <div class="badge badge--destructive">
                            Rejected
                        </div>
                    <?php else: ?>
                        <div class="badge badge--yellow">
                            Pending
                        </div>
                    <?php endif; ?>
                </div>

                <!-- Applicant email-->
                <div class="header__information">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-mail icon--sm--margin">
                        <rect width="20" height="16" x="2" y="4" rx="2" />
                        <path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" />
                    </svg>

                    <span>
                        <?= htmlspecialchars($application->getUser()->getEmail()) ?>
                    </span>
                </div>

                <!-- Aplicant name -->
                <div class="header__information">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-user-round icon--sm--margin">
                        <circle cx="12" cy="8" r="5" />
                        <path d="M20 21a8 8 0 0 0-16 0" />
                    </svg>
                    <span>
                        <?= htmlspecialchars($application->getUser()->getName()) ?>
                    </span>
                </div>

                <!-- Apply Date -->
                <div class="header__information">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-calendar-days icon--sm--margin">
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
                        <?= htmlspecialchars($application->getCreatedAt()->format('Y-m-d')) ?>
                    </span>
                </div>
            </div>
        </header>

        <!-- Status reason if any -->
        <?php if ($application->getStatusReason() != null) : ?>
            <div class="card__content">
                <h2 class="content__title">Status Reason</h2>
                <div class="content__rich-text">
                    <?= Sanitizer::sanitize($application->getStatusReason()) ?>
                </div>
            </div>
        <?php endif; ?>

        <!-- CV & PDF -->
        <section class="card__content">
            <h2 class="content__title">
                Curriculum vitae (CV)
            </h2>

            <iframe
                class="cv"
                title="Curriculum Vitae"
                src='<?= htmlspecialchars($application->getCvPath(), ENT_QUOTES, 'utf-8'); ?>'
                width='100%'
                height='600px'>

                <p>Your browser doesn't support iframes.
                    <a href='<?= htmlspecialchars($application->getCvPath(), ENT_QUOTES, 'utf-8'); ?>' target='_blank'>Click here to see the PDF file.</a>
                </p>
            </iframe>
        </section>


        <?php if ($application->getVideoPath() != null): ?>
            <section class="card__content">
                <h2 class="content__title">Introduction Video</h2>

                <video
                    class="video"
                    controls
                    width='100%'
                    height='auto'
                    preload='metadata'
                    controlsList='nodownload'
                    class='video-player'>
                    <source src='<?= htmlspecialchars($application->getVideoPath(), ENT_QUOTES, 'utf-8')  ?>'>
                    Your browser doesn't support HTML5 video.
                    <a href='<?= htmlspecialchars($application->getVideoPath(), ENT_QUOTES, 'utf-8')  ?>'>Download the video instead.</a>
                </video>
            </section>
        <?php endif; ?>

        <?php if ($application->getStatus() == ApplicationStatus::WAITING): ?>
            <!-- Accept / Reject -->
            <section class="card__content">
                <h2 class="content__title">
                    Application Verdict
                </h2>

                <form class="application-verdict__form" id="application-detail-form" action="/company/jobs/<?= htmlspecialchars($application->getJob()->getJobId(), ENT_QUOTES, 'utf-8'); ?>/applications/<?= htmlspecialchars($application->getApplicationId(), ENT_QUOTES, 'utf-8'); ?>" method="POST">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
                    <!-- Radio fields -->
                    <div class="form__group">
                        <label class="form__label
                            <?php if (isset($errorFields) && isset($errorFields['status'])):  ?>
                                <?= htmlspecialchars($errorFields['status'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                            <?php endif; ?>
                        ">
                            Status
                        </label>

                        <label class="radio-item">
                            <input type="radio" name="status" value="accepted" class="radio-input"
                                <?php if (isset($fields['status']) && $fields['status'] == 'accepted'): ?>
                                checked
                                <?php endif; ?>>
                            <span class="radio-custom"></span>
                            <span class="radio-label">Accept</span>
                        </label>

                        <label class="radio-item">
                            <input type="radio" name="status" value="rejected" class="radio-input"
                                <?php if (isset($fields['status']) && $fields['status'] == 'rejected'): ?>
                                checked
                                <?php endif; ?>>
                            <span class="radio-custom"></span>
                            <span class="radio-label">Reject</span>
                        </label>

                        <p class="form__error-message">
                            <?php if (isset($errorFields) && isset($errorFields['status'])):  ?>
                                <?= htmlspecialchars($errorFields['status'][0] ?? '') ?>
                            <?php endif; ?>
                        </p>
                    </div>

                    <!-- Rich text -->
                    <div class="form__group">
                        <label for="status-reason" class="form__label  
                            <?php if (isset($errorFields) && isset($errorFields['status-reason'])):  ?>
                                <?= htmlspecialchars($errorFields['status-reason'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                            <?php endif; ?>
                        ">
                            Status Reason
                        </label>

                        <div class="ql-wrapper">
                            <div id="status-reason-quill-editor">
                                <?= Sanitizer::sanitize($fields['status-reason'] ?? '') ?>
                            </div>
                            <textarea
                                id="hidden-status-reason-quill-editor"
                                name="status-reason"
                                class="textarea"></textarea>
                        </div>

                        <p class="form__error-message">
                            <?php if (isset($errorFields) && isset($errorFields['status-reason'])):  ?>
                                <?= htmlspecialchars($errorFields['status-reason'][0] ?? '') ?>
                            <?php endif; ?>
                        </p>
                    </div>


                    <!-- Submit button -->
                    <button class="button button--default-size button--default-color">Submit</button>
                </form>
            </section>
        <?php endif; ?>
    </article>
</main>