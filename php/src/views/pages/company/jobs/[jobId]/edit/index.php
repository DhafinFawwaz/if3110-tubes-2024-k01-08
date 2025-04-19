<?php
use src\utils\Csrf;
use src\utils\Sanitizer;

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
            Edit Job
        </h1>

        <!-- Form -->
        <form
            id="edit-job-form"
            class="form"
            action="/company/jobs/<?= htmlspecialchars($currentJobId, ENT_QUOTES, 'UTF-8') ?>/edit"
            method="POST"
            enctype="multipart/form-data">
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
                        <?= Sanitizer::sanitize($fields['description'] ?? '') ?>
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

            <!-- Is open -->
            <div class="form__group">
                <div class="form__box">
                    <div>
                        <label for="is-open" class="form__label 
                            <?php if (isset($errorFields) && isset($errorFields['is-open'])):  ?>
                                <?= htmlspecialchars($errorFields['is-open'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                            <?php endif; ?>
                        ">
                            Recruiting
                        </label>

                        <p class="form__label-description">
                            Open or close the job
                        </p>
                    </div>

                    <label class="switch">
                        <!-- False -->
                        <input type="hidden" name="is-open" value="0">
                        <!-- True -->
                        <input
                            id="is-open"
                            type="checkbox"
                            name="is-open"
                            value="1"
                            role="switch"
                            class="switch__input"
                            <?= (isset($fields['is-open']) && $fields['is-open'] == '1') ? 'checked' : ''; ?>>
                        <span class="switch__slider"></span>
                    </label>
                </div>
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

                <!-- Current value -->
                <div id="form-attachments" class="form__attachments">
                    <?php foreach ($fields['attachments'] as $attachment): ?>
                        <div class="attachment">
                            <img class="attachment__image" src="<?= htmlspecialchars($attachment->getFilePath(), ENT_QUOTES, 'UTF-8'); ?>" alt="Attachment" class="attachment">
                            <button data-attachment-id="<?= htmlspecialchars($attachment->getAttachmentId(), ENT_QUOTES, 'UTF-8'); ?>" type="button" class="button--destructive button attachment__delete-button" aria-label="Delete Image Button">
                                <svg class="attachment__delete-icon" xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-trash-2">
                                    <path d="M3 6h18" />
                                    <path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" />
                                    <path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" />
                                    <line x1="10" x2="10" y1="11" y2="17" />
                                    <line x1="14" x2="14" y1="11" y2="17" />
                                </svg>
                            </button>
                        </div>
                    <?php endforeach; ?>
                </div>

                <input id="attachments" class="input" name="attachments[]" type="file" accept="image/*" multiple />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['attachments'])):  ?>
                        <?= htmlspecialchars($errorFields['attachments'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <!-- Submit -->
            <button id="edit-job-submit" type="submit" class="button button--default-size button--default-color">
                Edit
            </button>
        </form>
    </section>
</main>