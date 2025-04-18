<?php
use src\utils\Csrf;
$csrfToken = Csrf::generateToken();
?>

<main class="main">
    <!-- Card -->
    <section class="card">
        <!-- Back button -->
        <a href="/company/jobs" class="card__back">
            <svg class="back__icon" xmlns="hsttp://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-arrow-left">
                <path d="m12 19-7-7 7-7" />
                <path d="M19 12H5" />
            </svg>

            <span>Back</span>
        </a>

        <!-- Title -->
        <h1 class="card__title">
            Create Job
        </h1>

        <!-- Form -->
        <form id="create-job-form" class="form" action="/company/jobs/create" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <!-- Position -->
            <div class="form__group">
                <label for="position" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['position'])):  ?>
                        <?= htmlspecialchars($errorFields['position'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Position
                </label>

                <input
                    name="position"
                    type="text"
                    placeholder="Fill in the position you're hiring for"
                    value="<?= htmlspecialchars($fields['position'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                    class="input" />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['position'])):  ?>
                        <?= htmlspecialchars($errorFields['position'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>


            <!-- Description (Rich Text) -->
            <div class="form__group">
                <label for="description" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['description'])):  ?>
                        <?= htmlspecialchars($errorFields['description'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Description
                </label>

                <div class="ql-wrapper">
                    <div id="description-quill-editor">
                        <?= $fields['description'] ?? '' ?>
                    </div>
                    <textarea
                        id="hidden-description-quill-editor"
                        name="description"
                        class="textarea"></textarea>
                </div>

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['description'])):  ?>
                        <?= htmlspecialchars($errorFields['description'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <div class="form__group--row">
                <!-- Job Type -->
                <div class="form__group">
                    <label for="job-type" class="form__label 
                        <?php if (isset($errorFields) && isset($errorFields['job-type'])):  ?>
                            <?= htmlspecialchars($errorFields['job-type'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                        <?php endif; ?>
                    ">
                        Job Type
                    </label>

                    <div class="select-wrapper--full">
                        <select class="custom-select" name="job-type" aria-label="Select an option">
                            <option value="" disabled hidden
                                <?= (!isset($fields['job-type']) || $fields['job-type'] === '') ? 'selected' : '' ?>>Select an option</option>
                            <option value="full-time"
                                <?= (isset($fields['job-type']) && $fields['job-type'] === 'full-time') ? 'selected' : '' ?>>Full-Time</option>
                            <option value="part-time"
                                <?= (isset($fields['job-type']) && $fields['job-type'] === 'part-time') ? 'selected' : '' ?>>Part-Time</option>
                            <option value="internship"
                                <?= (isset($fields['job-type']) && $fields['job-type'] === 'internship') ? 'selected' : '' ?>>Internship</option>
                        </select>
                        <svg class="custom-select__chevron-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="m6 9 6 6 6-6" />
                        </svg>
                    </div>

                    <p class="form__error-message">
                        <?php if (isset($errorFields) && isset($errorFields['job-type'])):  ?>
                            <?= htmlspecialchars($errorFields['job-type'][0] ?? '') ?>
                        <?php endif; ?>
                    </p>
                </div>

                <!-- Location Type -->
                <div class="form__group">
                    <label for="location-type" class="form__label 
                        <?php if (isset($errorFields) && isset($errorFields['location-type'])):  ?>
                            <?= htmlspecialchars($errorFields['location-type'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                        <?php endif; ?>
                    ">
                        Location Type
                    </label>

                    <div class="select-wrapper--full">
                        <select class="custom-select" name="location-type" aria-label="Select an option">
                            <option value="" disabled hidden
                                <?= (!isset($fields['location-type']) || $fields['location-type'] === '') ? 'selected' : '' ?>>Select an option</option>
                            <option value="on-site"
                                <?= (isset($fields['location-type']) && $fields['location-type'] === 'on-site') ? 'selected' : '' ?>>On-Site</option>
                            <option value="hybrid"
                                <?= (isset($fields['location-type']) && $fields['location-type'] === 'hybrid') ? 'selected' : '' ?>>Hybrid</option>
                            <option value="remote"
                                <?= (isset($fields['location-type']) && $fields['location-type'] === 'remote') ? 'selected' : '' ?>>Remote</option>
                        </select>
                        <svg class="custom-select__chevron-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="m6 9 6 6 6-6" />
                        </svg>
                    </div>

                    <p class="form__error-message">
                        <?php if (isset($errorFields) && isset($errorFields['location-type'])):  ?>
                            <?= htmlspecialchars($errorFields['location-type'][0] ?? '') ?>
                        <?php endif; ?>
                    </p>
                </div>
            </div>

            <!-- Attachments -->
            <div class="form__group">
                <label for="attachments" class="form__label 
                        <?php if (isset($errorFields) && isset($errorFields['attachments'])):  ?>
                            <?= htmlspecialchars($errorFields['attachments'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                        <?php endif; ?>
                    ">
                    Attachments
                </label>

                <input id="attachments" class="input" name="attachments[]" type="file" accept="image/*" multiple />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['attachments'])):  ?>
                        <?= htmlspecialchars($errorFields['attachments'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <!-- Submit -->
            <button type="submit" class="button button--default-size button--default-color">
                Create
            </button>
        </form>
    </section>
</main>